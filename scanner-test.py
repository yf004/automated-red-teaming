import sys
import json
import asyncio
import warnings
import nest_asyncio

from langgraph.graph import START, END, StateGraph
from langchain_core.messages import HumanMessage

from agents.prompts import scanner_input_generator_prompt
from agents.outputs import ScannerInputOutput, call_ollama_with_json
from tools.all_tools import PentestState

nest_asyncio.apply()
warnings.filterwarnings("ignore", category=ResourceWarning)

if len(sys.argv) < 3:
    print("Usage: python scanner-test.py <url> <scrape_file>")
    sys.exit(1)

MODEL = "gpt-oss:20b"

async def main():
    url = sys.argv[1]
    scrape_file = sys.argv[2]

    with open(scrape_file, "r", encoding="utf-8") as f:
        website_scrape = f.read()

    goal = "login with username 'admin' using nosql injection and retrieve ctf flag"

    async def scanner_input_structurer(state: PentestState):
        """
        Takes raw website scrape and structures scanner tool inputs.
        """

        prompt = f"""
{scanner_input_generator_prompt}

=== TARGET URL ===
{state['url']}

=== GOAL ===
{state['goal']}

=== WEBSITE SCRAPE ===
{state['website_scrape']}
"""

        result = await call_ollama_with_json(
            MODEL,
            prompt,
            ScannerInputOutput,
        )

        return {
            "scanner_tool_inputs": result["scanner_tool_inputs"],
        }

    graph = StateGraph(PentestState)
    graph.add_node("scanner_input_structurer", scanner_input_structurer)

    graph.add_edge(START, "scanner_input_structurer")
    graph.add_edge("scanner_input_structurer", END)

    workflow = graph.compile()

    state = await workflow.ainvoke(
        {
            "messages": [HumanMessage(content="Structure scanner inputs from website scrape")],
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
