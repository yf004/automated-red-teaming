from typing import TypedDict, Union
from pydantic import Field
from typing import TypedDict, Union
import json
import warnings
import nest_asyncio
from langchain_ollama.chat_models import ChatOllama
from langchain_core.messages import HumanMessage, AIMessage



nest_asyncio.apply()
warnings.filterwarnings("ignore", category=ResourceWarning)

class ExploitEvaluatorOutput(TypedDict):
    should_terminate: bool = Field(
        description="True if the pentest loop should terminate"
    )
    reason: str = Field(description="Reason for verdict")
    successful_payload: Union[None, dict[str, str]] = Field(
        description="""
If the loop should terminate and the exploit was successful, this will contain the payload that were successful for each field.
It should look like this:
"payloads": {
    "<field_name_1>": "<payload for field 1>",
    "<field_name_2>": "<payload for field 2>",
    …           : …
}
Else, this field should be empty/null.
Return ONLY valid JSON.
NO explanations. NO markdown. NO pre-text or post-text.
"""
    )


class AttackerOutput(TypedDict):
    final_output: list[dict[str, Union[str, dict]]]

class PlannerOutput(TypedDict):
    final_output: dict[str, Union[str, list]]


class CriticOutput(TypedDict):
    final_output: dict[str, Union[list[dict], dict]]
    
def get_json_schema_prompt(schema_class: type) -> str:
    """
    Generate a JSON schema prompt from a Pydantic TypedDict class.
    """
    if schema_class.__name__ == "CriticOutput":
        return """
{
  "final_output": {
    "analysis": [
      {
        "entry_point": "string (URL)",
        "page_url": "string (URL of the page with the form)",
        "payloads": {
          "field_name_1": "payload string",
          "field_name_2": "payload string"
        },
        "reflection": "string or null (full NoSQL command)",
        "analysis": "string (explanation)"
      }
    ],
    "recommendation": {
      "payloads": {
        "field1": "payload string",
        "field2": "payload string"
      },
      "reason": "string (why this payload should succeed)"
    }
  }
}
"""
    elif schema_class.__name__ == "PlannerOutput":
        return """
{
  "final_output": [
    {
      "entry_point": "string (URL)",
      "page_url": "string (URL of the page with the form)",
      "payload_sequence": [
        {
          "type": "string (e.g., boolean, union)",
          "payloads": {
            "field_name_1": "payload string",
            "field_name_2": "payload string"
          },
          "reason": "string (rationale)"
        }
      ],
      "justification": "string (brief summary)"
    }
  ]
}
"""
    elif schema_class.__name__ == "AttackerOutput":
        return """
{
  "final_output": [
    {
      "entry_point": "string (URL)",
      "page_url": "string (URL of the page with the form)",
      "payloads": {
        "field_name": "payload string"
      },
      "response_excerpt": "string (excerpt of response)",
      "notes": "string (observations)"
    }
  ]
}
"""
    elif schema_class.__name__ == "ExploitEvaluatorOutput":
        return """
{
  "should_terminate": boolean,
  "reason": "string (reason for verdict)",
  "successful_payload": null or {
    "field_name_1": "payload string",
    "field_name_2": "payload string"
  }
}
"""
    
    hints = schema_class.__annotations__
    schema_desc = "{\n"
    for field_name, field_type in hints.items():
        field_info = schema_class.__dict__.get(field_name)
        desc = field_info.description if hasattr(field_info, 'description') else ""
        type_str = str(field_type).replace("typing.", "")
        schema_desc += f'  "{field_name}": {type_str}'
        if desc:
            schema_desc += f'  // {desc}'
        schema_desc += '\n'
    schema_desc += "}"
    
    return schema_desc


def safe_parse_json(content: str) -> dict:
    """
    Safely parse JSON from model output, handling markdown code blocks.
    """
    content = content.strip()
    if content.startswith("```"):
        lines = content.split("\n")
        lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        content = "\n".join(lines).strip()
    
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        start = content.find('{')
        end = content.rfind('}') + 1
        if start != -1 and end > start:
            return json.loads(content[start:end])
        raise

async def call_ollama_with_json(model_name: str, prompt: str, schema_class: type, max_retries: int = 3) -> dict:
    """
    Call Ollama with JSON mode enabled and parse the response.
    Includes retry logic for malformed JSON and server errors.
    """
    schema_name = schema_class.__name__
    
    for attempt in range(max_retries):
        try:
            llm = ChatOllama(
                model=model_name,
                format="json",
                temperature=0.1,
                timeout=120,
                verbose=False
            )
            schema_desc = get_json_schema_prompt(schema_class)
            enhanced_prompt = f"""{prompt}

CRITICAL: You MUST respond with a valid JSON object that EXACTLY matches this structure:
{schema_desc}

RULES:
1. Return ONLY valid JSON
2. NO explanations before or after the JSON
3. NO markdown code blocks (no ```)
4. NO additional text
5. Ensure all required fields are present
6. Follow the exact structure shown above

Your response should start with {{ and end with }}"""
            
            response = await llm.ainvoke([HumanMessage(content=enhanced_prompt)])
            result = safe_parse_json(response.content)
            if schema_name == "CriticOutput":
                if "final_output" in result:
                    if "analysis" not in result["final_output"] or "recommendation" not in result["final_output"]:
                        raise ValueError(f"Invalid CriticOutput structure. Missing required fields in final_output.")
                elif "analysis" in result and "recommendation" in result:
                    result = {"final_output": result}
                else:
                    raise ValueError(f"Invalid CriticOutput structure. Missing required fields.")
            
            return result
            
        except Exception as e:
            print('Error: ', e)
            raise
    
    raise ValueError(f"Failed to get valid JSON after {max_retries} attempts")

