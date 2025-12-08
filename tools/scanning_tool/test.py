import asyncio
from typing import List, Union, Type
import ctypes
import json

from pydantic import BaseModel, Field

from langchain_community.chat_models import ChatOllama
from langchain.tools import BaseTool
from langgraph.prebuilt import create_react_agent

# Import your tool
from .nosql_scanner import ScanForNoSQLITool

MODEL = "gpt-oss:20b"

agent_prompt = """Scan this API for NoSQL injection using the tool provided:
    URL: http://localhost:3000/api/login
    Fields: username,password
"""

async def main():
    agent = create_react_agent(
        model=ChatOllama(model=MODEL, temperature=0, verbose=False),
        prompt=agent_prompt,
        name="critic_agent",
        tools=[ScanForNoSQLITool()],
        debug=True
    )

    # Run the agent
    state = PentestState(
        input="Scan http://localhost:3000/api/login for NoSQLi in username and password fields"
    )

    result = await agent.ainvoke(state)
    print("\n=== FINAL OUTPUT ===")
    print(result)

if __name__ == "__main__":
    asyncio.run(main())

