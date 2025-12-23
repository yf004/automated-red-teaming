import sys
import json
import asyncio
import warnings
import nest_asyncio
import requests
from langgraph.graph import START, END, StateGraph
from langchain_core.messages import HumanMessage
from agents.prompts import scanner_input_generator_prompt
from agents.outputs import ScannerInputOutput, call_ollama_with_json
from typing import TypedDict, Optional, Any, List
# from tools.scanning_tool.nosql_scanner import ScanForNoSQLITool
from langchain.tools import BaseTool
from typing import List, Union, Type
from pydantic import BaseModel, Field
import sys
from typing import TypedDict, Union, Optional, Any, List
import json
import asyncio
import warnings
import nest_asyncio

from langchain_ollama.chat_models import ChatOllama
from agents.prompts import (
    scanner_input_generator_prompt,  
    planner_agent_prompt, 
    attacker_agent_prompt, 
    critic_agent_prompt, 
    exploit_evaluator_agent_prompt, 
    report_writer_agent_prompt, 
)
from agents.outputs import(
    ExploitEvaluatorOutput, 
    AttackerOutput, 
    PlannerOutput, 
    CriticOutput,
    ScannerInputOutput, 
    call_ollama_with_json
)
from langchain_core.exceptions import OutputParserException
from langgraph.graph import END, START, StateGraph
from langgraph.prebuilt import create_react_agent
from pydantic import Field
from langchain_core.messages import HumanMessage, AIMessage

from tools.all_tools import (
    PentestState,
    attacker_tools,
    planner_tools,
    report_writer_tools,
)

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
        result = res[0: self._state % len(res)]
        self._state += 1
        return result

    async def _arun(self, url: str, fields: Union[List[str], str]) -> str:
        """Async version (runs sync code in a thread)."""
        return await asyncio.to_thread(self._run, url, fields)


class ScannerStructurerState(TypedDict):
    url: str
    goal: str
    website_scrape: str
    messages: List[Any]
    scanner_tool_inputs: Optional[Any]


nest_asyncio.apply()
warnings.filterwarnings("ignore", category=ResourceWarning)

if len(sys.argv) < 2:
    print("Usage: python scanner-test.py <url>")
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
    url = sys.argv[1]

    goal = "login with username 'admin' using nosql injection and retrieve ctf flag"

    print("[*] Fetching initial website scrape...")
    website_scrape = fetch_initial_scrape(url)

    async def scanner_input_structurer(state: ScannerStructurerState):
        """
        Structure scanner inputs directly from website scrape.
        """

        prompt = f"""
{scanner_input_generator_prompt}

=== TARGET URL ===
{state['url']}

=== GOAL ===
{state['goal']}

=== INITIAL WEBSITE SCRAPE (RAW) ===
{state['website_scrape']}
"""

        result = await call_ollama_with_json(
            MODEL,
            prompt,
            ScannerInputOutput,
        )

        return {
            "scanner_tool_inputs": result["scanner_tool_inputs"]
        }

    graph = StateGraph(ScannerStructurerState)
    graph.add_node("scanner_input_structurer", scanner_input_structurer)

    graph.add_edge(START, "scanner_input_structurer")
    graph.add_edge("scanner_input_structurer", END)

    workflow = graph.compile()

    state = await workflow.ainvoke(
        {
            "messages": [
                HumanMessage(content="Generate structured scanner inputs from website scrape")
            ],
            "url": url,
            "goal": goal,
            "website_scrape": website_scrape,
            "scanner_tool_inputs": None,
        }
    )

    print("\n=== STRUCTURED SCANNER INPUTS ===")
    scanner_inputs = state["scanner_tool_inputs"]
    print(json.dumps(scanner_inputs, indent=2))

    scanner_tool = ScanForNoSQLITool()
    res = await scanner_tool.arun({
        "url": scanner_inputs["endpoint"],
        "fields": scanner_inputs["fields"],
    })
    
    print("\n=== NOSQLI SCANNER OUTPUT===")
    print(res)

 

    




if __name__ == "__main__":
    asyncio.run(main())
