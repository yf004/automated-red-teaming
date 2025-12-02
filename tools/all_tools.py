from typing import TypedDict, Optional, Union, Annotated
import os
from langchain_chroma import Chroma
import json
from langchain_core.documents import Document

from langchain.tools.retriever import create_retriever_tool
from langchain_community.agent_toolkits import FileManagementToolkit
from .toolkit import Toolkit as NonBrowserToolkit
from langchain_community.utilities import GoogleSerperAPIWrapper
from langchain_community.utilities.requests import TextRequestsWrapper
from langchain_core.tools import Tool, tool
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langgraph.prebuilt import InjectedState
from langgraph.prebuilt.chat_agent_executor import AgentStateWithStructuredResponse
from langchain_ollama import OllamaEmbeddings

from mcp_client import get_mcp_tools

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


search = GoogleSerperAPIWrapper()
search_tool = Tool(
    name="search",
    func=search.run,
    description="Use this to search the web for information",
)

def web_tools():
    toolkit = NonBrowserToolkit()
    return toolkit.get_tools()

def rag(json_path: str, name: str, description: str):
    # Create a persistent directory for the vector store
    persist_directory = "vector_store"
    os.makedirs(persist_directory, exist_ok=True)
    
    print("Starting RAG initialization...")
    
    # Initialize embeddings
    print("Initializing Ollama embeddings...")
    embeddings = OllamaEmbeddings(
        model="nomic-embed-text",
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

# Offline RAG using local JSON
nosqli_rag_tool = rag(
    json_path="nosqli_docs.json",  # JSON file generated ahead of time
    name="retrieve_nosqli_information",
    description="Search and return information about NoSQL Injection and payloads from NoSQL Injection Cheat Sheets.",
)


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
        (await get_mcp_tools("scanner_mcp.json")) + [search_tool] + web_tools()
    )

async def planner_tools():
    return (await get_mcp_tools("planner_mcp.json")) + [search_tool, nosqli_rag_tool]


def attacker_tools():
    return web_tools()


def report_writer_tools():
    return file_management_tools + [search_tool]
