from __future__ import annotations
from typing import List, Dict, Any, Type, ClassVar
from pydantic import BaseModel
from langchain_community.agent_toolkits.base import BaseToolkit
from langchain_core.tools import BaseTool
from pydantic.v1 import Extra

import requests
from bs4 import BeautifulSoup


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


class ExtractTextTool(BaseTool):
    name: str = "extract_text"
    description: str = "Extracts visible text from HTML content."
    args_schema: ClassVar[Type[BaseModel]] = ExtractTextArgs

    def _run(self, html: str) -> str:
        soup = BeautifulSoup(html, "html.parser")
        return soup.get_text(separator="\n", strip=True)

    async def _arun(self, html: str) -> str:
        return self._run(html)


class ExtractHTMLTool(BaseTool):
    name: str = "extract_html"
    description: str = "Returns the full HTML (input unchanged)."
    args_schema: ClassVar[Type[BaseModel]] = ExtractHTMLArgs

    def _run(self, html: str) -> str:
        return html

    async def _arun(self, html: str) -> str:
        return self._run(html)


class ExtractLinksTool(BaseTool):
    name: str = "extract_links"
    description: str = "Extracts all hyperlinks (hrefs) from HTML content."
    args_schema: ClassVar[Type[BaseModel]] = ExtractLinksArgs

    def _run(self, html: str) -> List[str]:
        soup = BeautifulSoup(html, "html.parser")
        return [a["href"] for a in soup.find_all("a", href=True)]

    async def _arun(self, html: str) -> List[str]:
        return self._run(html)


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
            # ExtractTextTool(),
            # ExtractHTMLTool(),
            ExtractLinksTool(),
            ParseFormTool(),
            SubmitFormTool()
        ]
