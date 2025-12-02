from typing import TypedDict, Union
from pydantic import Field

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
    
