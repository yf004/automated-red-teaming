from typing import TypedDict, Optional, Union, Annotated
import os
from langchain_chroma import Chroma
import json
from langchain_core.documents import Document

from langchain.tools.retriever import create_retriever_tool
from langchain_community.agent_toolkits import FileManagementToolkit
from langchain_community.utilities import GoogleSerperAPIWrapper
from langchain_community.utilities.requests import TextRequestsWrapper
from langchain_core.tools import Tool, tool
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langgraph.prebuilt import InjectedState
from langgraph.prebuilt.chat_agent_executor import AgentStateWithStructuredResponse
from langchain_ollama import OllamaEmbeddings
from langchain_community.utilities.requests import TextRequestsWrapper
from langchain_community.agent_toolkits.openapi.toolkit import RequestsToolkit
from langchain_community.tools.playwright.utils import create_async_playwright_browser
from tools.selenium.selenium import (
    ClickButtonInput,
    DescribeWebsiteInput,
    FillOutFormInput,
    FindFormInput,
    GoogleSearchInput,
    ScrollInput,
    SeleniumWrapper,
)
from langchain.tools.base import BaseTool

from typing import List
from mcp_client import get_mcp_tools
from tools.scanning_tool.nosql_scanner import ScanForNoSQLITool

class PentestState(AgentStateWithStructuredResponse):
    tries: int
    should_terminate: bool
    reason: str
    url: str
    attempts: list[dict[str, Union[dict, str]]]
    recommendation: dict
    successful_payload: Union[None, dict[str, str]]
    payloads: list
    goal: str = ""

    raw_attacker_output: Optional[str]
    raw_planner_output: Optional[str]
    raw_critic_output: Optional[str]
    initial_scan_report: Optional[str]


search = GoogleSerperAPIWrapper()
search_tool = Tool(
    name="search",
    func=search.run,
    description="Use this to search the web for information",
)

def get_selenium_tools() -> List[BaseTool]:
    """Get the tools that will be used by the AI agent."""
    selenium = SeleniumWrapper()
    tools: List[BaseTool] = [
        Tool(
            name="goto",
            func=selenium.describe_website,
            description="useful for when you need visit a link or a website",
            args_schema=DescribeWebsiteInput,
        ),
        Tool(
            name="click",
            func=selenium.click_button_by_text,
            description="useful for when you need to click a button/link",
            args_schema=ClickButtonInput,
        ),
        Tool(
            name="find_form",
            func=selenium.find_form_inputs,
            description=(
                "useful for when you need to find out input forms given a url. Returns"
                " the input fields to fill out"
            ),
            args_schema=FindFormInput,
        ),
        Tool(
            name="fill_form",
            func=selenium.fill_out_form,
            description=(
                "useful for when you need to fill out a form on the current website."
                " Input should be a json formatted string"
            ),
            args_schema=FillOutFormInput,
        ),
        Tool(
            name="scroll",
            func=selenium.scroll,
            description=(
                "useful for when you need to scroll up or down on the current website"
            ),
            args_schema=ScrollInput,
        ),
        Tool(
            name="google_search",
            func=selenium.google_search,
            description="perform a google search",
            args_schema=GoogleSearchInput,
        )
    ]
    return tools



def rag(json_path: str, name: str, description: str):
    # Create a persistent directory for the vector store
    persist_directory = "vector_store"
    os.makedirs(persist_directory, exist_ok=True)
    
    print("Starting RAG initialization...")
    
    # Initialize embeddings
    print("Initializing Ollama embeddings...")
    embeddings = OllamaEmbeddings(
        model="gpt-oss-20b",
        base_url="http://localhost:11434"
    )
    print("Ollama embeddings initialized...")
    
    # Check if vector store exists and load/create accordingly
    print("Checking for existing vector store...")
    
    # Check if the vector store already exists
    if os.path.exists(persist_directory) and any(os.scandir(persist_directory)):
        # Load existing vector store
        vectorstore = Chroma(
            persist_directory=persist_directory, 
            embedding_function=embeddings
        )
        count = vectorstore._collection.count()
        print(f"Loaded existing vector store with {count} documents")
    else:
        # Create new vector store from JSON
        print("Creating new vector store from local JSON...")

        # Load from local JSON file
        with open(json_path, "r", encoding="utf-8") as f:
            raw_docs = json.load(f)

        docs_list = [
            Document(page_content=doc["content"], metadata=doc.get("metadata", {}))
            for doc in raw_docs
        ]
        print(f"Loaded {len(docs_list)} documents from {json_path}")

        text_splitter = RecursiveCharacterTextSplitter.from_tiktoken_encoder(
            chunk_size=100, chunk_overlap=50
        )
        doc_splits = text_splitter.split_documents(docs_list)
        print(f"Split into {len(doc_splits)} chunks...")

        # Create new vector store with persistence
        vectorstore = Chroma.from_documents(
            documents=doc_splits,
            embedding=embeddings,
            persist_directory=persist_directory
        )
        print("Vector store created and persisted...")
    
    retriever = vectorstore.as_retriever()
    retriever_tool = create_retriever_tool(retriever, name, description)
    print("RAG initialization complete!")
    return retriever_tool

nosqli_rag_tool = rag(
    json_path="nosqli_docs.json", 
    name="retrieve_nosqli_information",
    description="Search and return information about NoSQL Injection and payloads from NoSQL Injection Cheat Sheets.",
)

requests_tools = RequestsToolkit(
    requests_wrapper=TextRequestsWrapper(headers={}),
    allow_dangerous_requests=True,
).get_tools()

file_management_tools = FileManagementToolkit(
    root_dir=str("sandbox"),
).get_tools()



@tool
def get_attempts(state: Annotated[PentestState, InjectedState]) -> int:
    """
    Returns the number of attempts made by the Pentest Agents.
    """
    return state["tries"]


async def scanner_tools():
    return (
        (await get_mcp_tools("scanner_mcp.json")) + [search_tool, ScanForNoSQLITool()] + get_selenium_tools()
    )

async def planner_tools():
    return (await get_mcp_tools("planner_mcp.json")) + [search_tool, nosqli_rag_tool]

def attacker_tools():
    return get_selenium_tools() + requests_tools

def report_writer_tools():
    return file_management_tools + [search_tool]


