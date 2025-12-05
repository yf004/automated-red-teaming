from langchain.tools import BaseTool
from typing import List, Union, Type
from pydantic import BaseModel, Field
import ctypes
import json
import asyncio


class ScanForNoSQLIInput(BaseModel):
    """Input schema for NoSQL injection scanner."""
    url: str = Field(description="The target URL (API endpoint) to scan for NoSQL injection vulnerabilities")
    fields: Union[List[str], str] = Field(description="Form fields to test, as a list of strings of field names eg. ['username', 'password']")

class ScanForNoSQLITool(BaseTool):
    name: str = "scan_for_nosqli"
    description: str = "Scans a web application for NoSQL injection vulnerabilities by testing form fields"
    args_schema: Type[BaseModel] = ScanForNoSQLIInput
    
    def _run(self, url: str, fields: Union[List[str], str]) -> str:
        try:
            if isinstance(fields, str):
                fields = [fields]
            
            library = ctypes.CDLL("./library.so")
            library.run.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
            library.run.restype = ctypes.c_void_p
            
            json_dict = {item: "" for item in fields}
            request = json.dumps(json_dict, indent=2)
            
            output = library.run(
                url.encode("utf-8"),
                request.encode("utf-8")
            )
            
            report = ctypes.string_at(output).decode("utf-8")
            return f"Scan completed for {url}\n\n{report}"
        
        except FileNotFoundError:
            return "Error: library.so not found."
        except Exception as e:
            return f"Error during scan: {str(e)}"

    async def _arun(self, url: str, fields: Union[List[str], str]) -> str:
        """Async version (runs sync code in a thread)."""
        return await asyncio.to_thread(self._run, url, fields)


