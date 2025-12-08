# test_direct_tool.py

import asyncio
from langchain_community.chat_models import ChatOllama
from nosql_scanner import ScanForNoSQLITool

MODEL = "gpt-oss:20b"

async def main():
    tool = ScanForNoSQLITool()
    # Directly test your tool
    result = tool.run(tool_input={
        "url": "https://vegetational-tranquilly-annalee.ngrok-free.dev/level1/login",
        "fields": ["username", "password"]
    })


    print("\n=== TOOL OUTPUT ===")
    print(result)

if __name__ == "__main__":
    asyncio.run(main())
