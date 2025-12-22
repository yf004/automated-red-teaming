import sys
import json
import asyncio
import warnings
import nest_asyncio

from langchain_ollama.chat_models import ChatOllama
from langgraph.graph import START, END, StateGraph
from langgraph.prebuilt import create_react_agent
from langchain_core.messages import HumanMessage

from agents.prompts import scanner_input_generator_prompt
from agents.outputs import ScannerInputOutput, call_ollama_with_json
from tools.all_tools import PentestState, scanner_input_tools

nest_asyncio.apply()
warnings.filterwarnings("ignore", category=ResourceWarning)

if len(sys.argv) < 2:
    print("Usage: python scanner-test.py <url>")
    sys.exit(1)


async def run_scanner_tool(scanner_inputs: dict) -> str:
    """Run the real NoSQL scanner"""
    from tools.scanning_tool.nosql_scanner import ScanForNoSQLITool

    scanner = ScanForNoSQLITool()
    return await scanner.arun(scanner_inputs)


async def main():
    url = sys.argv[1]
    MODEL = 'gpt-oss:20b'
    goal = 'login with username \'admin\' using nosql injection and retrieve ctf flag'
    # ============================================================
    # SCANNER INPUT GENERATOR AGENT
    # ============================================================
    async def scanner_input_generator(state: PentestState):
        agent = create_react_agent(
            model=ChatOllama(model=MODEL, temperature=0),
            prompt=scanner_input_generator_prompt,
            name="scanner_input_generator",
            tools=await scanner_input_tools(),
            state_schema=PentestState,
            debug=True,
        )

        resp = await agent.ainvoke(state)
        raw = resp["messages"][-1].content

        print("\n=== RAW SCANNER INPUT (LLM) ===")
        print(raw)

        return {
            "raw_scanner_input": raw,
            "messages": [resp["messages"][-1]],
        }

    async def scanner_input_structurer(state: PentestState):
        result = await call_ollama_with_json(
            MODEL,
            state["raw_scanner_input"],
            ScannerInputOutput,
        )

        return {
            "scanner_tool_inputs": result["scanner_tool_inputs"]
        }

    # ============================================================
    # GRAPH (scanner only)
    # ============================================================
    graph = StateGraph(PentestState)
    graph.add_node("scanner_input_generator", scanner_input_generator)
    graph.add_node("scanner_input_structurer", scanner_input_structurer)

    graph.add_edge(START, "scanner_input_generator")
    graph.add_edge("scanner_input_generator", "scanner_input_structurer")
    graph.add_edge("scanner_input_structurer", END)

    workflow = graph.compile()

    # ============================================================
    # RUN
    # ============================================================
    state = await workflow.ainvoke(
        {
            "messages": [HumanMessage(content=f"Target URL: {url}\nGoal: {goal}")],
            "url": url,
            "goal": goal,
            "raw_scanner_input": None,
            "scanner_tool_inputs": None,
        }
    )

    scanner_inputs = state["scanner_tool_inputs"]

    print("\n=== STRUCTURED SCANNER INPUTS ===")
    print(json.dumps(scanner_inputs, indent=2))

    print("\n=== RUNNING NOSQL SCANNER ===")
    report = await run_scanner_tool(scanner_inputs)

    print("\n=== SCANNER OUTPUT ===")
    print(report)


if __name__ == "__main__":
    asyncio.run(main())
