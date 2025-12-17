import sys
from typing import TypedDict, Union, Optional, Any, List
import json
import asyncio
import warnings
import nest_asyncio

from langchain_ollama.chat_models import ChatOllama
from agents.prompts import (
    scanner_input_generator_prompt,  # NEW: generates tool inputs instead of running tools
    planner_agent_prompt, 
    attacker_agent_prompt, 
    critic_agent_prompt, 
    exploit_evaluator_agent_prompt, 
    report_writer_agent_prompt, 
    supervisor_agent_prompt
)
from agents.outputs import(
    ExploitEvaluatorOutput, 
    AttackerOutput, 
    PlannerOutput, 
    CriticOutput,
    ScannerInputOutput,  # NEW: for scanner tool inputs
    call_ollama_with_json
)
from langchain_core.exceptions import OutputParserException
from langgraph.graph import END, START, StateGraph
from langgraph.prebuilt import create_react_agent
from langgraph_supervisor import create_supervisor
from pydantic import Field
from langchain_core.messages import HumanMessage, AIMessage

from tools.all_tools import (
    PentestState,
    attacker_tools,
    get_attempts,
    planner_tools,
    report_writer_tools,
)

nest_asyncio.apply()
warnings.filterwarnings("ignore", category=ResourceWarning)

if len(sys.argv) < 3:
    print("Usage: python main.py <url> <model>")
    sys.exit(1)


async def run_scanner_tool(scanner_inputs: dict) -> str:
    """
    Run the NoSQL scanner tool OUTSIDE the agentic framework.
    This function executes the actual scanner with the provided inputs.
    
    Args:
        scanner_inputs: Dictionary containing tool parameters from the agent
        
    Returns:
        The scanner report as a string
    """
    from tools.scanning_tool.nosql_scanner import ScanForNoSQLITool
    
    print(f"\n{'='*80}")
    print("EXECUTING NOSQL SCANNER TOOL (OUTSIDE AGENT FRAMEWORK)")
    print(f"{'='*80}")
    print(f"Scanner Inputs: {json.dumps(scanner_inputs, indent=2)}")
    print(f"{'='*80}\n")
    
    # Initialize the scanner tool
    scanner_tool = ScanForNoSQLITool()
    
    # Run the scanner with the provided inputs
    # This may take some time, which is why we run it outside the agent
    scan_report = await scanner_tool.arun(scanner_inputs)
    
    print(f"\n{'='*80}")
    print("SCANNER TOOL EXECUTION COMPLETE")
    print(f"Report length: {len(scan_report)} characters")
    print(f"{'='*80}\n")
    
    return scan_report


async def main():
    MODEL = sys.argv[2]

    # ============================================================================
    # PHASE 1: SCANNER INPUT GENERATION
    # ============================================================================
    async def scanner_input_generator(state: PentestState):
        """
        Agent that generates the INPUTS for the NoSQL scanner tool,
        but does NOT execute the tool itself.
        """
        scanner_input_agent = create_react_agent(
            model=ChatOllama(model=MODEL, temperature=0, streaming=False),
            prompt=scanner_input_generator_prompt,
            name="scanner_input_generator",
            tools=await planner_tools(),  # Tools that help explore, but no actual scanner
            state_schema=PentestState,
            debug=True,
        )
        
        resp = await scanner_input_agent.ainvoke(state)
        
        # The agent's final output should describe what inputs to pass to the scanner
        raw_output = resp["messages"][-1].content
        
        print(f"\n{'='*80}")
        print("SCANNER INPUT GENERATOR OUTPUT")
        print(f"{'='*80}")
        print(f"Output: {raw_output[:500]}...")
        print(f"{'='*80}\n")
        
        return {
            "messages": [resp["messages"][-1]],
            "raw_scanner_input": raw_output,
        }
    
    async def scanner_input_structurer(state: PentestState):
        """Structure scanner input generator output using Ollama JSON mode."""
        content = state["raw_scanner_input"]
        
        try:
            result = await call_ollama_with_json(MODEL, content, ScannerInputOutput)
            
            # Extract the structured scanner inputs
            scanner_inputs = result.get("scanner_tool_inputs", {})
            
            return {
                "scanner_tool_inputs": scanner_inputs,
                "raw_scanner_input": None,
            }
        except Exception as e:
            print(f"\n=== ERROR IN SCANNER_INPUT_STRUCTURER ===")
            print(f"Error: {e}")
            print(f"Raw content length: {len(content)}")
            print(f"Raw content preview: {content[:500]}...")
            print(f"==========================================\n")
            raise

    # ============================================================================
    # PHASE 2: PENTEST AGENTS (NO SCANNER)
    # ============================================================================
    async def planner(state: PentestState):
        """Planner agent returns raw natural language output."""
        planner_agent = create_react_agent(
            model=ChatOllama(model=MODEL, temperature=0, streaming=False, verbose=False),
            prompt=planner_agent_prompt,
            name="planner_agent",
            tools=await planner_tools(),
            state_schema=PentestState,
            debug=True,
        )
        
        resp = await planner_agent.ainvoke(state)
        
        return {
            "messages": [resp["messages"][-1]],
            "raw_planner_output": resp["messages"][-1].content,
        }
    
    async def planner_structurer(state: PentestState):
        """Structure planner output using Ollama JSON mode."""
        content = state["raw_planner_output"]
        
        try:
            result = await call_ollama_with_json(MODEL, content, PlannerOutput)
            
            final_output = result.get("final_output", {})
            
            if isinstance(final_output, dict):
                final_output = [final_output]
            
            if not isinstance(final_output, list):
                raise ValueError(f"Planner structurer did not return payloads in a valid list format. Got type: {type(final_output)}")
                        
            return {
                "payloads": final_output,
                "raw_planner_output": None,
            }
        except Exception as e:
            print(f"\n=== ERROR IN PLANNER_STRUCTURER ===")
            print(f"Error: {e}")
            print(f"Raw content length: {len(content)}")
            print(f"Raw content preview: {content[:500]}...")
            print(f"====================================\n")
            raise

    async def attacker(state: PentestState):
        """Attacker agent returns raw natural language output (no structured output)."""
        attacker_agent = create_react_agent(
            model=ChatOllama(model=MODEL, temperature=0, streaming=False, verbose=False),
            prompt=attacker_agent_prompt,
            name="attacker_agent",
            tools=attacker_tools(),
            state_schema=PentestState,
            debug=True,
        )
        
        resp = await attacker_agent.ainvoke(state)
        
        return {
            "messages": [resp["messages"][-1]],
            "raw_attacker_output": resp["messages"][-1].content,
            "attempts": state["attempts"],
        }
    
    async def attacker_structurer(state: PentestState):
        """Structure attacker output using Ollama JSON mode."""
        content = state["raw_attacker_output"]
        
        try:
            result = await call_ollama_with_json(MODEL, content, AttackerOutput)
            
            if "final_output" not in result or not isinstance(result["final_output"], list):
                raise ValueError(f"Attacker structurer did not return valid attempts. Got keys: {list(result.keys()) if isinstance(result, dict) else 'N/A'}")
            
            new_attempts = result["final_output"]
            
            return {
                "attempts": state["attempts"] + new_attempts,
                "raw_attacker_output": None,
            }
        except Exception as e:
            print(f"\n=== ERROR IN ATTACKER_STRUCTURER ===")
            print(f"Error: {e}")
            print(f"Raw content length: {len(content)}")
            print(f"Raw content preview: {content[:500]}...")
            print(f"=====================================\n")
            raise

    async def critic(state: PentestState):
        """Critic agent returns raw natural language output."""
        critic_agent = create_react_agent(
            model=ChatOllama(model=MODEL, temperature=0, streaming=False, verbose=False),
            prompt=critic_agent_prompt,
            name="critic_agent",
            tools=await planner_tools(),
            state_schema=PentestState,
            debug=True,
        )
        
        resp = await critic_agent.ainvoke(state)
        
        return {
            "messages": [resp["messages"][-1]],
            "raw_critic_output": resp["messages"][-1].content,
        }
    
    async def critic_structurer(state: PentestState):
        """Structure critic output using Ollama JSON mode."""
        content = state["raw_critic_output"]
        
        try:
            result = await call_ollama_with_json(MODEL, content, CriticOutput)
            
            if "final_output" in result:
                final_output = result["final_output"]
            elif "analysis" in result and "recommendation" in result:
                final_output = result
            else:
                raise ValueError(f"Critic structurer: unexpected structure. Keys: {list(result.keys())}")
            
            if not isinstance(final_output, dict):
                raise ValueError(f"Final output is not a dict. Type: {type(final_output)}")
            
            if "analysis" not in final_output:
                raise ValueError(f"Final output missing 'analysis' key. Keys: {list(final_output.keys())}")
                
            if "recommendation" not in final_output:
                raise ValueError(f"Final output missing 'recommendation' key. Keys: {list(final_output.keys())}")
            
            if not isinstance(final_output["analysis"], list):
                final_output["analysis"] = [final_output["analysis"]]
            
            if not isinstance(final_output["recommendation"], dict):
                raise ValueError(f"Recommendation is not a dict. Type: {type(final_output['recommendation'])}")
                        
            c = state["attempts"].copy()
            
            for analysis_entry in final_output["analysis"]:
                if not isinstance(analysis_entry, dict):
                    print(f"⚠ Warning: Skipping non-dict analysis entry: {analysis_entry}")
                    continue
                    
                for attempt_entry in c:
                    if (
                        analysis_entry.get("page_url") == attempt_entry.get("page_url")
                        and analysis_entry.get("payloads") == attempt_entry.get("payloads")
                    ):
                        attempt_entry.update(analysis_entry)
            
            return {
                "attempts": c,
                "recommendation": final_output["recommendation"],
                "raw_critic_output": None,
            }
        except Exception as e:
            print(f"\n=== ERROR IN CRITIC_STRUCTURER ===")
            print(f"Error: {e}")
            print(f"Error type: {type(e).__name__}")
            print(f"Raw content length: {len(content)}")
            print(f"Raw content preview: {content[:1000]}...")
            if 'result' in locals():
                print(f"Parsed result keys: {list(result.keys()) if isinstance(result, dict) else 'N/A'}")
                if isinstance(result, dict) and len(str(result)) < 2000:
                    print(f"Full result: {json.dumps(result, indent=2)}")
            print(f"===================================\n")
            raise

    async def exploit_evaluator(state: PentestState):
        """Exploit evaluator using Ollama JSON mode for structured output."""
        prompt = f"""
{exploit_evaluator_agent_prompt}

[CURRENT STATE]
Attempts: {state['attempts']}
Tries: {state['tries']}
Goal: {state['goal']}

Analyze the attempts and decide if the loop should terminate.
NOTE: Do NOT terminate to request re-scanning. The scanner has already run and cannot be called again.
"""
        
        try:
            result = await call_ollama_with_json(MODEL, prompt, ExploitEvaluatorOutput)
            
            if "reason" not in result:
                raise ValueError("Exploit Evaluator did not provide a reason for termination")
            if "should_terminate" not in result:
                raise ValueError("Exploit Evaluator did not indicate whether to terminate or not")

            should_terminate = result["should_terminate"]
            reason = result["reason"]
            
            print(f"\n{'='*60}")
            print(f"EXPLOIT EVALUATOR DECISION:")
            print(f"  Terminate: {should_terminate}")
            print(f"  Reason: {reason}")
            print(f"  Try #{state['tries'] + 1}")
            print(f"{'='*60}\n")

            return {
                "messages": [AIMessage(content=str(result))],
                "should_terminate": should_terminate,
                "reason": reason,
                "tries": state["tries"] + 1,
                "attempts": [] if should_terminate else state["attempts"],
                "recommendation": "" if should_terminate else state["recommendation"],
                "successful_payload": result.get("successful_payload", {}),
            }
        except Exception as e:
            print(f"\n=== ERROR IN EXPLOIT_EVALUATOR ===")
            print(f"Error: {e}")
            print(f"Prompt length: {len(prompt)}")
            print(f"===================================\n")
            raise

    def exploit_evaluator_decision(state: PentestState):
        """
        Route decision after exploit evaluator.
        Now only routes between critic and ending (no scanner option).
        """
        if state["should_terminate"] or state["tries"] > 10:
            return "end"
        else:
            return "critic_agent"

    # ============================================================================
    # PHASE 1 GRAPH: SCANNER INPUT GENERATION
    # ============================================================================
    scanner_input_graph = StateGraph(PentestState)
    scanner_input_graph.add_node("scanner_input_generator", scanner_input_generator)
    scanner_input_graph.add_node("scanner_input_structurer", scanner_input_structurer)
    
    scanner_input_graph.add_edge(START, "scanner_input_generator")
    scanner_input_graph.add_edge("scanner_input_generator", "scanner_input_structurer")
    scanner_input_graph.add_edge("scanner_input_structurer", END)
    
    scanner_input_workflow = scanner_input_graph.compile()

    # ============================================================================
    # PHASE 2 GRAPH: PENTEST LOOP (NO SCANNER)
    # ============================================================================
    pentest_subgraph = StateGraph(PentestState)
    pentest_subgraph.add_node("planner_agent", planner)
    pentest_subgraph.add_node("planner_structurer", planner_structurer)
    pentest_subgraph.add_node("attacker_agent", attacker)
    pentest_subgraph.add_node("attacker_structurer", attacker_structurer)
    pentest_subgraph.add_node("critic_agent", critic)
    pentest_subgraph.add_node("critic_structurer", critic_structurer)
    pentest_subgraph.add_node("exploit_evaluator_agent", exploit_evaluator)

    # Start directly at planner (scanner already ran externally)
    pentest_subgraph.add_edge(START, "planner_agent")
    pentest_subgraph.add_edge("planner_agent", "planner_structurer")
    pentest_subgraph.add_edge("planner_structurer", "attacker_agent")
    pentest_subgraph.add_edge("attacker_agent", "attacker_structurer")
    pentest_subgraph.add_edge("attacker_structurer", "exploit_evaluator_agent")
    pentest_subgraph.add_conditional_edges(
        "exploit_evaluator_agent",
        exploit_evaluator_decision,
        {"end": END, "critic_agent": "critic_agent"},
    )
    pentest_subgraph.add_edge("critic_agent", "critic_structurer")
    # Critic goes back to planner, NOT scanner
    pentest_subgraph.add_edge("critic_structurer", "planner_agent")
    
    pentest_agents = pentest_subgraph.compile(name="pentest_agents")

    # ============================================================================
    # PHASE 3: REPORT WRITER
    # ============================================================================
    report_writer_agent = create_react_agent(
        model=ChatOllama(model=MODEL, temperature=0.3, streaming=False),
        prompt=report_writer_agent_prompt,
        name="report_writer_agent",
        tools=report_writer_tools(),
        state_schema=PentestState,
        debug=True,
    )

    # ============================================================================
    # MAIN EXECUTION FLOW
    # ============================================================================
    url = sys.argv[1]
    goal = input('Input goal: ')
    
    print(f"\n{'='*80}")
    print(f"TARGET URL: {url}")
    print(f"GOAL: {goal}")
    print(f"{'='*80}\n")

    
    # scanner_input_state = await scanner_input_workflow.ainvoke(
    #     {
    #         "messages": [HumanMessage(content=f"Target URL: {url}\nGoal: {goal}")],
    #         "tries": 0,
    #         "should_terminate": False,
    #         "reason": "",
    #         "url": url,
    #         "attempts": [],
    #         "recommendation": {},
    #         "successful_payload": None,
    #         "payloads": [],
    #         "structured_response": None,
    #         "raw_attacker_output": None,
    #         "raw_planner_output": None,
    #         "raw_critic_output": None,
    #         "raw_scanner_input": None,
    #         "scanner_tool_inputs": None,
    #         "initial_scan_report": None,
    #         "goal": goal
    #     },
    #     {"recursion_limit": 50},
    # )
    
    # scanner_inputs = scanner_input_state.get("scanner_tool_inputs", {})
    
    # if not scanner_inputs:
    #     print("ERROR: Scanner input generator did not produce valid inputs")
    #     sys.exit(1)
    

    
    initial_scan_report = f'''
=== TOOL OUTPUT ===
Scan completed for {url}/login

URL: {url}/login
Method: POST
Running Error based scan...
Running Boolean based scan...
Running Timing based scan...

=== RESULTS ===
Found Blind NoSQL Injection:
        URL: {url}/login
        param:
        Injection: =true: ';return true;'}//, false: "';return false;'}//"

Found Blind NoSQL Injection:
        URL: {url}/login
        param:
        Injection: =true: ' || 'a'=='a' || 'a'=='a, false: "' && 'a'!='a' && 'a'!='a"

Found Blind NoSQL Injection:
        URL: {url}/login
        param:
        Injection: =true: ';return true;', false: "';return false;'"

Found Blind NoSQL Injection:
        URL: {url}/login
        param:
        Injection: =true: ' || 'a'=='a' || 'a'=='a//, false: "' && 'a'!='a' && 'a'!='a//"

Found Timing based NoSQL Injection:
        URL: {url}/login
        param:
        Injection: ="';sleep(500);'"

Found Timing based NoSQL Injection:
        URL: {url}/login
        param:
        Injection: ="';sleep(500);'}//"
    '''

    
    flag = True
    while flag:
        try:
            pentest_result = await pentest_agents.ainvoke(
                {
                    "messages": [
                        HumanMessage(content=f"Target URL: {url}\nGoal: {goal}"),
                        AIMessage(content=f"Scanner Report:\n{initial_scan_report}")
                    ],
                    "tries": 0,
                    "should_terminate": False,
                    "reason": "",
                    "url": url,
                    "attempts": [],
                    "recommendation": {},
                    "successful_payload": None,
                    "payloads": [],
                    "structured_response": None,
                    "raw_attacker_output": None,
                    "raw_planner_output": None,
                    "raw_critic_output": None,
                    "initial_scan_report": initial_scan_report, 
                    "entry_point": url+'/login',
                    "goal": goal
                },
                {"recursion_limit": 100},
            )
            flag = False
        except OutputParserException as e:
            print("\n--- INVALID JSON FROM MODEL ---")
            print(e.llm_output)
            print("--------------------------------")
    
    # ============================================================================
    # STEP 4: Generate report
    # ============================================================================
    print(f"\n{'='*80}")
    print("STEP 4: GENERATING REPORT")
    print(f"{'='*80}\n")
    
    await report_writer_agent.ainvoke(pentest_result)
    
    print(f"\n{'='*80}")
    print("PENTEST COMPLETE")
    print(f"{'='*80}\n")


if __name__ == "__main__":
    asyncio.run(main())