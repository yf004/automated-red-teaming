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


class ScannerInputOutput(TypedDict):
    """
    Output from the scanner input generator agent.
    Contains the structured inputs that should be passed to the NoSQL scanner tool.
    """
    scanner_tool_inputs: dict[str, Union[str, list, dict]] = Field(
        description="""
The inputs that should be passed to the NoSQL scanner tool.
This should contain all necessary parameters:
- target_url: The URL to scan
- endpoints_to_test: List of endpoints
- fields: List of fields in the endpoint form
""")


def print_planner_output(data: dict) -> None:
    """
    Pretty print Planner Agent output.
    """
    print("\n" + "="*80)
    print("PLANNER AGENT OUTPUT")
    print("="*80)
    
    final_output = data.get("final_output", [])
    
    for idx, entry in enumerate(final_output, 1):
        print(f"\n[Entry Point #{idx}]")
        print(f"  Entry Point: {entry.get('entry_point', 'N/A')}")
        print(f"  Page URL: {entry.get('page_url', 'N/A')}")
        print(f"  Justification: {entry.get('justification', 'N/A')}")
        
        payload_sequence = entry.get('payload_sequence', [])
        print(f"\n  Payload Sequence ({len(payload_sequence)} payload(s)):")
        
        for pidx, payload in enumerate(payload_sequence, 1):
            print(f"\n    [Payload #{pidx}]")
            print(f"      Type: {payload.get('type', 'N/A')}")
            print(f"      Reason: {payload.get('reason', 'N/A')}")
            print(f"      Payloads:")
            
            payloads_dict = payload.get('payloads', {})
            for field_name, field_payload in payloads_dict.items():
                print(f"        - {field_name}: {field_payload}")
        
        print("\n" + "-"*80)
    
    print()


def print_critic_output(data: dict) -> None:
    """
    Pretty print Critic Agent output.
    """
    print("\n" + "="*80)
    print("CRITIC AGENT OUTPUT")
    print("="*80)
    
    final_output = data.get("final_output", {})
    
    print("\n[ANALYSIS]")
    analysis_list = final_output.get("analysis", [])
    
    for idx, analysis in enumerate(analysis_list, 1):
        print(f"\n  Analysis #{idx}:")
        print(f"    Entry Point: {analysis.get('entry_point', 'N/A')}")
        print(f"    Page URL: {analysis.get('page_url', 'N/A')}")
        print(f"    Reflection: {analysis.get('reflection', 'None')}")
        print(f"    Analysis: {analysis.get('analysis', 'N/A')}")
        
        print(f"    Payloads Tested:")
        payloads = analysis.get('payloads', {})
        for field_name, payload in payloads.items():
            print(f"      - {field_name}: {payload}")
        print()
    
    print("\n[RECOMMENDATION]")
    recommendation = final_output.get("recommendation", {})
    print(f"  Reason: {recommendation.get('reason', 'N/A')}")
    print(f"  Recommended Payloads:")
    
    rec_payloads = recommendation.get('payloads', {})
    for field_name, payload in rec_payloads.items():
        print(f"    - {field_name}: {payload}")
    
    print("\n" + "="*80 + "\n")


def print_attacker_output(data: dict) -> None:
    """
    Pretty print Attacker Agent output.
    """
    print("\n" + "="*80)
    print("ATTACKER AGENT OUTPUT")
    print("="*80)
    
    final_output = data.get("final_output", [])
    
    for idx, attempt in enumerate(final_output, 1):
        print(f"\n[Attempt #{idx}]")
        print(f"  Entry Point: {attempt.get('entry_point', 'N/A')}")
        print(f"  Page URL: {attempt.get('page_url', 'N/A')}")
        
        print(f"  Payloads:")
        payloads = attempt.get('payloads', {})
        for field_name, payload in payloads.items():
            print(f"    - {field_name}: {payload}")
        
        print(f"\n  Response Excerpt:")
        response = attempt.get('response_excerpt', 'N/A')
        if len(response) > 200:
            response = response[:200] + "..."
        print(f"    {response}")
        
        print(f"\n  Notes: {attempt.get('notes', 'N/A')}")
        print("\n" + "-"*80)
    
    print()


def print_evaluator_output(data: dict) -> None:
    """
    Pretty print Exploit Evaluator output.
    """
    print("\n" + "="*80)
    print("EXPLOIT EVALUATOR OUTPUT")
    print("="*80)
    
    should_terminate = data.get('should_terminate', False)
    reason = data.get('reason', 'N/A')
    successful_payload = data.get('successful_payload')
    
    print(f"\n  Should Terminate: {should_terminate}")
    print(f"  Reason: {reason}")
    
    if successful_payload:
        print(f"\n  Successful Payload:")
        for field_name, payload in successful_payload.items():
            print(f"    - {field_name}: {payload}")
    else:
        print(f"\n  Successful Payload: None")
    
    print("\n" + "="*80 + "\n")


def print_scanner_input_output(data: dict) -> None:
    """
    Pretty print Scanner Input Generator output.
    """
    print("\n" + "="*80)
    print("SCANNER INPUT GENERATOR OUTPUT")
    print("="*80)
    
    scanner_inputs = data.get("scanner_tool_inputs", {})
    
    print("\n  Scanner Tool Inputs:")
    for key, value in scanner_inputs.items():
        if isinstance(value, (list, dict)):
            print(f"    {key}: {json.dumps(value, indent=6)}")
        else:
            print(f"    {key}: {value}")
    
    print("\n" + "="*80 + "\n")

    
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
        "entry_point": "string (FULL URL)",
        "page_url": "string (FULL URL of the page with the form)",
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
    elif schema_class.__name__ == "ScannerInputOutput":
        return """
{
  "scanner_tool_inputs": {
    "target_url": "string (the URL to scan)",
    "endpoint": "string (the ENDPOINT API URL to test),
    "fields": {
      ["list of endpoint parameters"]
    }
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


async def call_ollama_with_json(model_name: str, prompt: str, schema_class: type, max_retries: int = 3, print_output: bool = True) -> dict:
    """
    Call Ollama with JSON mode enabled and parse the response.
    Includes retry logic for malformed JSON and server errors.
    
    Args:
        model_name: Name of the Ollama model to use
        prompt: The prompt to send to the model
        schema_class: TypedDict class defining the expected output schema
        max_retries: Maximum number of retry attempts
        print_output: Whether to pretty print the output (default: True)
    
    Returns:
        Parsed JSON dictionary matching the schema
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
            
            if print_output:
                if schema_name == "PlannerOutput":
                    print_planner_output(result)
                elif schema_name == "CriticOutput":
                    print_critic_output(result)
                elif schema_name == "AttackerOutput":
                    print_attacker_output(result)
                elif schema_name == "ExploitEvaluatorOutput":
                    print_evaluator_output(result)
                elif schema_name == "ScannerInputOutput":
                    print_scanner_input_output(result)
            
            return result
            
        except Exception as e:
            print(f'Error on attempt {attempt + 1}/{max_retries}: {e}')
            if attempt == max_retries - 1:
                raise
    
    raise ValueError(f"Failed to get valid JSON after {max_retries} attempts")