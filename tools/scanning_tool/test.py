import sys
import asyncio
from langchain_community.chat_models import ChatOllama
from nosql_scanner import ScanForNoSQLITool


async def main(url):
    if not url:
        print("Error: No URL provided")
        print("Usage: python script.py <url>")
        return
    
    tool = ScanForNoSQLITool()
    result = tool.run(tool_input={
        "url": url + "/level2/login",
        "fields": ["username", "password"]
    })

    print("\n=== TOOL OUTPUT ===")
    print(result)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Error: Please provide a URL as an argument")
        print("Usage: python script.py <url>")
        sys.exit(1)
    
    url = sys.argv[1].rstrip('/')  # Remove trailing slash if present
    asyncio.run(main(url))