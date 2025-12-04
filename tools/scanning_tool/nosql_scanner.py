from langchain.tools import BaseTool
from typing import List, Union, Type
from pydantic import BaseModel, Field
import ctypes
import json


class ScanForNoSQLIInput(BaseModel):
    """Input schema for NoSQL injection scanner."""
    url: str = Field(description="The target URL (API endpoint) to scan for NoSQL injection vulnerabilities")
    fields: Union[List[str], str] = Field(description="Form fields to test, as a list of strings of field names eg. ['username', 'password']")


class ScanForNoSQLITool(BaseTool):
    name: str = "scan_for_nosqli"
    description: str = "Scans a web application for NoSQL injection vulnerabilities by testing form fields"
    args_schema: Type[BaseModel] = ScanForNoSQLIInput
    
    def _run(self, url: str, fields: Union[List[str], str]) -> str:
        """Execute the NoSQL injection scan."""
        try:
            # Convert single field to list if needed
            if isinstance(fields, str):
                fields = [fields]
            
            # Load the shared library
            library = ctypes.CDLL("./library.so")
            library.run.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
            library.run.restype = ctypes.c_void_p
            
            # Prepare the request payload
            json_dict = {item: "" for item in fields}
            request = json.dumps(json_dict, indent=2)
            
            # Execute the scan
            output = library.run(
                url.encode('utf-8'),
                request.encode('utf-8')
            )
            
            # Retrieve and return the report
            report = ctypes.string_at(output).decode('utf-8')
            
            return f"Scan completed for {url}\n\n{report}"
            
        except FileNotFoundError:
            return f"Error: library.so not found. Please ensure the scanner library is in the current directory."
        except Exception as e:
            return f"Error during scan: {str(e)}"
    
    async def _arun(self, url: str, fields: Union[List[str], str]) -> str:
        """Async version of the scan (not implemented)."""
        raise NotImplementedError("Async scan not supported")





# Alternative decorator version if you prefer @tool syntax
def get_scanner_tool_decorator():
    """Alternative implementation using the @tool decorator."""
    from langchain.tools import tool
    
    @tool
    def scan_for_nosqli_tool(url: str, fields: Union[List[str], str]) -> str:
        """Scans a web application for NoSQL injection vulnerabilities by testing form fields.
        
        Args:
            url: The target URL to scan
            fields: Form fields to test (list of field names or single field)
            
        Returns:
            String containing the scan report
        """
        try:
            if isinstance(fields, str):
                fields = [fields]
            
            library = ctypes.CDLL("./library.so")
            library.run.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
            library.run.restype = ctypes.c_void_p
            
            json_dict = {item: "" for item in fields}
            request = json.dumps(json_dict, indent=2)
            
            output = library.run(
                url.encode('utf-8'),
                request.encode('utf-8')
            )
            
            report = ctypes.string_at(output).decode('utf-8')
            
            return f"Scan completed for {url}\n\n{report}"
            
        except FileNotFoundError:
            return f"Error: library.so not found. Please ensure the scanner library is in the current directory."
        except Exception as e:
            return f"Error during scan: {str(e)}"
    
    return scan_for_nosqli_tool


# Example usage in a LangChain agent
if __name__ == "__main__":
    # Get the tool
    scanner_tool = ScanForNoSQLITool()
    
    # Use the tool
    result = scanner_tool.run({
        "url": "http://localhost:3000/level1/login",
        "fields": ['username', 'password']
    })
    
    print(result)
