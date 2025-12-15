# test_direct_tool.py

import asyncio
from langchain_community.chat_models import ChatOllama
from nosql_scanner import ScanForNoSQLITool

MODEL = "gpt-oss:20b"

async def main():
    tool = ScanForNoSQLITool()
    result = tool.run(tool_input={
        # "url": "http://thzse-213-245-98-157.a.free.pinggy.link/level1/login",
        "url": "http://localhost:3000/level1/login",
        "fields": ["username", "password"]
    })

    print("\n=== TOOL OUTPUT ===")
    print(result)

if __name__ == "__main__":
    asyncio.run(main())
