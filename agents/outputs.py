from typing import TypedDict, Union
from pydantic import Field
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
    endpoint: str = Field(description="The full URL endpoint to target")
    payloads: list[dict[str, str]] = Field(
        description="""
List of 5 payloads to test. Each payload should have:
- field_name: Which field to inject into
- payload: The actual injection string
- description: What this tests
"""
    )


class CriticOutput(TypedDict):
    decision: str = Field(
        description="Must be one of: 'rescan', 'replan', 'success', 'failure'"
    )
    reasoning: str = Field(
        description="Explanation of why this decision was made"
    )
    suggestions: str = Field(
        description="Specific suggestions for next iteration if applicable"
    )


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
- endpoint: Specific endpoint to test
- fields: List of fields in the endpoint form
""")


def print_planner_output(data: dict) -> None:
    """
    Pretty print Planner Agent output.
    """
    print("\n" + "="*80)
    print("PLANNER AGENT OUTPUT")
    print("="*80)
    
    endpoint = data.get("endpoint", "N/A")
    payloads = data.get("payloads", [])
    
    print(f"\nTarget Endpoint: {endpoint}")
    print(f"\nGenerated {len(payloads)} Payloads:\n")
    
    for idx, payload in enumerate(payloads, 1):
        print(f"  [Payload #{idx}]")
        print(f"    Field: {payload.get('field_name', 'N/A')}")
        print(f"    Payload: {payload.get('payload', 'N/A')}")
        print(f"    Description: {payload.get('description', 'N/A')}")
        print()
    
    print("="*80 + "\n")


def print_critic_output(data: dict) -> None:
    """
    Pretty print Critic Agent output.
    """
    print("\n" + "="*80)
    print("CRITIC AGENT OUTPUT")
    print("="*80)
    
    decision = data.get("decision", "N/A")
    reasoning = data.get("reasoning", "N/A")
    suggestions = data.get("suggestions", "N/A")
    
    print(f"\nDecision: {decision.upper()}")
    print(f"\nReasoning:")
    print(f"  {reasoning}")
    print(f"\nSuggestions:")
    print(f"  {suggestions}")
    
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
    # Handle dict type for free-form schemas (like reports)
    if schema_class == dict:
        return """
{
  (free-form JSON object with appropriate structure for the task)
}
"""
    
    if schema_class.__name__ == "PlannerOutput":
        return """
{
  "endpoint": "string (full URL endpoint to target)",
  "payloads": [
    {
      "field_names": [list of fields to inject into],
      "payloads": [list of injection strings (order with respect to field_names)],
      "description": "string (what this tries)"
    },
    ... (5 total payloads)
  ]
}
"""
    
    elif schema_class.__name__ == "CriticOutput":
        return """
{
  "decision": "rescan|replan|success|failure",
  "reasoning": "string (explanation of decision)",
  "suggestions": "string (specific suggestions for next iteration)"
}
"""

    elif schema_class.__name__ == "ScannerInputOutput":
        return """
{
  "scanner_tool_inputs": {
    "target_url": "string (the main URL to scan)",
    "endpoint": "string (the FULL ENDPOINT API URL to test)",
    "fields": ["list", "of", "field", "names"]
  }
}
"""
    
    elif schema_class.__name__ == "ExploitEvaluatorOutput":
        return """
{
  "should_terminate": true/false,
  "reason": "string (reason for verdict)",
  "successful_payload": {
    "field_name_1": "payload_1",
    "field_name_2": "payload_2"
  } OR null
}
"""
    
    # Fallback for other schemas
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
    
    # Remove markdown code blocks
    if content.startswith("```"):
        lines = content.split("\n")
        lines = lines[1:]  # Remove first ```json or ```
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]  # Remove last ```
        content = "\n".join(lines).strip()
    
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        # Try to extract JSON from the content
        start = content.find('{')
        end = content.rfind('}') + 1
        if start != -1 and end > start:
            return json.loads(content[start:end])
        raise


async def call_ollama_with_json(
    model_name: str, 
    prompt: str, 
    schema_class: type, 
    max_retries: int = 3, 
    print_output: bool = True
) -> dict:
    """
    Call Ollama with JSON mode enabled and parse the response.
    Includes retry logic for malformed JSON and server errors.
    
    Args:
        model_name: Name of the Ollama model to use
        prompt: The prompt to send to the model
        schema_class: TypedDict class defining the expected output schema (or dict for free-form)
        max_retries: Maximum number of retry attempts
        print_output: Whether to pretty print the output (default: True)
    
    Returns:
        Parsed JSON dictionary matching the schema
    """
    schema_name = schema_class.__name__ if hasattr(schema_class, '__name__') else 'dict'
    
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
            
            # Validate result structure (skip validation for dict schema)
            if schema_name == "CriticOutput":
                required_fields = ["decision", "reasoning", "suggestions"]
                if not all(field in result for field in required_fields):
                    raise ValueError(f"Invalid CriticOutput structure. Missing required fields.")
                
                valid_decisions = ["rescan", "replan", "success", "failure"]
                if result["decision"] not in valid_decisions:
                    raise ValueError(f"Invalid decision: {result['decision']}. Must be one of {valid_decisions}")
            
            elif schema_name == "PlannerOutput":
                if "endpoint" not in result or "payloads" not in result:
                    raise ValueError(f"Invalid PlannerOutput structure. Missing required fields.")
                if not isinstance(result["payloads"], list):
                    raise ValueError(f"'payloads' must be a list")
            
            elif schema_name == "ScannerInputOutput":
                if "scanner_tool_inputs" not in result:
                    raise ValueError(f"Invalid ScannerInputOutput structure. Missing 'scanner_tool_inputs' field.")
            
            # Pretty print the output
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
            # Wait a bit before retrying
            import asyncio
            await asyncio.sleep(1)
    
    raise ValueError(f"Failed to get valid JSON after {max_retries} attempts")