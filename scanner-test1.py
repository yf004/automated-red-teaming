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
    print(json.dumps(state["scanner_tool_inputs"], indent=2))


if __name__ == "__main__":
    asyncio.run(main())
