import sys
from typing import TypedDict, Union, Optional, Any, List
import json

if len(sys.argv) < 3:
    print("Usage: python main.py <url> <model>")
    sys.exit(1)

import asyncio
import getpass
import os
import warnings

import nest_asyncio
from langchain.chat_models import init_chat_model
from langchain_core.messages import HumanMessage, AIMessage, BaseMessage
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.callbacks.manager import CallbackManagerForLLMRun
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, START, StateGraph
from langgraph.prebuilt import create_react_agent
from langgraph_supervisor import create_supervisor
from pydantic import Field

from langchain_ollama.chat_models import ChatOllama
from agents.prompts import (
    scanner_agent_prompt, 
    planner_agent_prompt, 
    attacker_agent_prompt, 
    critic_agent_prompt, 
    exploit_evaluator_agent_prompt, 
    report_writer_agent_prompt, 
    supervisor_agent_prompt
)
from agents.outputs import ExploitEvaluatorOutput, AttackerOutput, PlannerOutput, CriticOutput
from langchain_core.exceptions import OutputParserException


from tools.all_tools import (
    PentestState,
    attacker_tools,
    get_attempts,
    planner_tools,
    report_writer_tools,
    scanner_tools,
)

nest_asyncio.apply()
warnings.filterwarnings("ignore", category=ResourceWarning)

def _set_if_undefined(var: str):
    if not os.environ.get(var):
        os.environ[var] = getpass.getpass(f"Please provide your {var}")


def get_json_schema_prompt(schema_class: type) -> str:
    """
    Generate a JSON schema prompt from a Pydantic TypedDict class.
    """
    if schema_class.__name__ == "CriticOutput":
        return """
{
  "final_output": {
    "analysis": [
      {
        "entry_point": "string (URL)",
        "page_url": "string (URL of the page with the form)",
        "payloads": {
          "field_name_1": "payload string",
          "field_name_2": "payload string"
        },
        "reflection": "string or null (full NoSQL command)",
        "analysis": "string (explanation)"
      }
    ],
    "recommendation": {
      "payloads": {
        "field1": "payload string",
        "field2": "payload string"
      },
      "reason": "string (why this payload should succeed)"
    }
  }
}
"""
    elif schema_class.__name__ == "PlannerOutput":
        return """
{
  "final_output": [
    {
      "entry_point": "string (URL)",
      "page_url": "string (URL of the page with the form)",
      "payload_sequence": [
        {
          "type": "string (e.g., boolean, union)",
          "payloads": {
            "field_name_1": "payload string",
            "field_name_2": "payload string"
          },
          "reason": "string (rationale)"
        }
      ],
      "justification": "string (brief summary)"
    }
  ]
}
"""
    elif schema_class.__name__ == "AttackerOutput":
        return """
{
  "final_output": [
    {
      "entry_point": "string (URL)",
      "page_url": "string (URL of the page with the form)",
      "payloads": {
        "field_name": "payload string"
      },
      "response_excerpt": "string (excerpt of response)",
      "notes": "string (observations)"
    }
  ]
}
"""
    elif schema_class.__name__ == "ExploitEvaluatorOutput":
        return """
{
  "should_terminate": boolean,
  "reason": "string (reason for verdict)",
  "successful_payload": null or {
    "field_name_1": "payload string",
    "field_name_2": "payload string"
  }
}
"""
    
    hints = schema_class.__annotations__
    schema_desc = "{\n"
    for field_name, field_type in hints.items():
        field_info = schema_class.__dict__.get(field_name)
        desc = field_info.description if hasattr(field_info, 'description') else ""
        type_str = str(field_type).replace("typing.", "")
        schema_desc += f'  "{field_name}": {type_str}'
        if desc:
            schema_desc += f'  // {desc}'
        schema_desc += '\n'
    schema_desc += "}"
    
    return schema_desc


def safe_parse_json(content: str) -> dict:
    """
    Safely parse JSON from model output, handling markdown code blocks.
    """
    content = content.strip()
    if content.startswith("```"):
        lines = content.split("\n")
        lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        content = "\n".join(lines).strip()
    
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        start = content.find('{')
        end = content.rfind('}') + 1
        if start != -1 and end > start:
            return json.loads(content[start:end])
        raise


async def call_ollama_with_json(model_name: str, prompt: str, schema_class: type, max_retries: int = 3) -> dict:
    """
    Call Ollama with JSON mode enabled and parse the response.
    Includes retry logic for malformed JSON and server errors.
    """
    schema_name = schema_class.__name__
    
    for attempt in range(max_retries):
        try:
            llm = ChatOllama(
                model=model_name,
                format="json",
                temperature=0.1,
                timeout=120,
            )
            schema_desc = get_json_schema_prompt(schema_class)
            enhanced_prompt = f"""{prompt}

CRITICAL: You MUST respond with a valid JSON object that EXACTLY matches this structure:
{schema_desc}

RULES:
1. Return ONLY valid JSON
2. NO explanations before or after the JSON
3. NO markdown code blocks (no ```)
4. NO additional text
5. Ensure all required fields are present
6. Follow the exact structure shown above

Your response should start with {{ and end with }}"""
            
            response = await llm.ainvoke([HumanMessage(content=enhanced_prompt)])
            result = safe_parse_json(response.content)
            if schema_name == "CriticOutput":
                if "final_output" in result:
                    if "analysis" not in result["final_output"] or "recommendation" not in result["final_output"]:
                        raise ValueError(f"Invalid CriticOutput structure. Missing required fields in final_output.")
                elif "analysis" in result and "recommendation" in result:
                    result = {"final_output": result}
                else:
                    raise ValueError(f"Invalid CriticOutput structure. Missing required fields.")
            
            return result
            
        except Exception as e:
            print('Error: ', e)
            raise
    
    raise ValueError(f"Failed to get valid JSON after {max_retries} attempts")


async def main():
    MODEL = sys.argv[2]

    scanner_agent = create_react_agent(
        model=ChatOllama(model=MODEL, temperature=0),
        prompt=scanner_agent_prompt,
        name="scanner_agent",
        tools=await scanner_tools(),
        state_schema=PentestState,
        debug=True,
    )

    
    async def planner(state: PentestState):
        """Planner agent returns raw natural language output."""
        planner_agent = create_react_agent(
            model=ChatOllama(model=MODEL, temperature=0),
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
            model=ChatOllama(model=MODEL, temperature=0),
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
            model=ChatOllama(model=MODEL, temperature=0),
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
                    # Use .get() for safer access
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
        if state["should_terminate"] or state["tries"] > 10:
            return "supervisor_agent"
        else:
            return "critic_agent"

    pentest_subgraph = StateGraph(PentestState)
    pentest_subgraph.add_node("planner_agent", planner)
    pentest_subgraph.add_node("planner_structurer", planner_structurer)
    pentest_subgraph.add_node("attacker_agent", attacker)
    pentest_subgraph.add_node("attacker_structurer", attacker_structurer)
    pentest_subgraph.add_node("critic_agent", critic)
    pentest_subgraph.add_node("critic_structurer", critic_structurer)
    pentest_subgraph.add_node("exploit_evaluator_agent", exploit_evaluator)

    pentest_subgraph.add_edge(START, "planner_agent")
    pentest_subgraph.add_edge("planner_agent", "planner_structurer")
    pentest_subgraph.add_edge("planner_structurer", "attacker_agent")
    pentest_subgraph.add_edge("attacker_agent", "attacker_structurer")
    pentest_subgraph.add_edge("attacker_structurer", "exploit_evaluator_agent")
    pentest_subgraph.add_conditional_edges(
        "exploit_evaluator_agent",
        exploit_evaluator_decision,
        {"supervisor_agent": END, "critic_agent": "critic_agent"},
    )
    pentest_subgraph.add_edge("critic_agent", "critic_structurer")
    pentest_subgraph.add_edge("critic_structurer", "planner_agent")
    pentest_agents = pentest_subgraph.compile(name="pentest_agents")

    report_writer_agent = create_react_agent(
        model=ChatOllama(model=MODEL, temperature=0.3),
        prompt=report_writer_agent_prompt,
        name="report_writer_agent",
        tools=report_writer_tools(),
        state_schema=PentestState,
        debug=True,
    )

    supervisor = create_supervisor(
        model=ChatOllama(model=MODEL, temperature=0),
        agents=[scanner_agent, pentest_agents, report_writer_agent],
        prompt=supervisor_agent_prompt,
        add_handoff_back_messages=True,
        output_mode="last_message",
        state_schema=PentestState,
        tools=[get_attempts],
    ).compile()

    url = sys.argv[1]
    goal = input('Input goal: ')
    
    print(f"\n{'='*60}")
    print(f"TARGET URL: {url}")
    print(f"GOAL: {goal}")
    print(f"{'='*60}\n")

    flag = True
    while flag: 
        try:
            result = await supervisor.ainvoke(
                {
                    "messages": [HumanMessage(content=f"Target URL: {url}\nGoal: {goal}")],
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
                    "goal": goal
                },
                {"recursion_limit": 100},
            )
            flag = False
        except OutputParserException as e:
            print("\n--- INVALID JSON FROM MODEL ---")
            print(e.llm_output)
            print("--------------------------------")


if __name__ == "__main__":
    asyncio.run(main())
