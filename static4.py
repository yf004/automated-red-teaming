import asyncio
from typing import List, Union, Type
from langchain.tools import BaseTool
from pydantic import BaseModel, Field

class ScanForNoSQLIInput(BaseModel):
    """Input schema for NoSQL injection scanner."""
    url: str = Field(description="The target URL (API endpoint) to scan for NoSQL injection vulnerabilities")
    fields: Union[List[str], str] = Field(description="Form fields to test, as a list of strings of field names eg. ['username', 'password']")


class ScanForNoSQLITool(BaseTool):
    name: str = "scan_for_nosqli"
    description: str = "Scans a web application for NoSQL injection vulnerabilities by testing form fields"
    args_schema: Type[BaseModel] = ScanForNoSQLIInput

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._state = 0  # keeps track of last returned index

    def _run(self, url: str, fields: Union[List[str], str]) -> str:
        res = [
            f'''
Found Error NoSQL Injection:
        URL: {url}
        param:
        Injection: {{"foo": 1}}=
''',
            f'''
Found Error NoSQL Injection:
        URL: {url}
        param:
        Injection: {{"foo": 1}}=
''',
            f'''
Found Blind NoSQL Injection:
        URL: {url}
        param:
        Injection: =true: {{"$where":  "return true"}}, false: {{"$where":  "return false"}}
''',
            f'''
Found Blind NoSQL Injection:
        URL: {url}
        param:
        Injection: =true: {{"$where":  "return true"}}, false: {{"$or": [{{"foo":"1"}},{{"foo":"1"}}]}}
''',
            f'''
Found Blind NoSQL Injection:
        URL: {url}
        param:
        Injection: =true: {{"$or": [{{}},{{"foo":"1"}}]}}, false: {{"$or": [{{"foo":"1"}},{{"foo":"1"}}]}}
''',
            f'''
Found Timing based NoSQL Injection:
        URL: {url}
        param:
        Injection: Whole Body={{"$where":  "sleep(500)"}}
''']

        # get the current result and increment counter
        result = res[0:self._state % len(res)+1]
        result = '\n'.join(result)
        self._state += 1
        return result

    async def _arun(self, url: str, fields: Union[List[str], str]) -> str:
        """Async version (runs sync code in a thread)."""
        return await asyncio.to_thread(self._run, url, fields)

