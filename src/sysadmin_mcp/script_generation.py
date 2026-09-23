"""Provider output framing is separate from script syntax and execution policy."""
import json
import re

from .dynamic_execution import Scripts

SCRIPT_RESPONSE_FORMAT = {
    'type': 'json_schema',
    'json_schema': {
        'name': 'host_script_draft', 'strict': True,
        'schema': {
            'type': 'object', 'additionalProperties': False,
            'properties': {'script': {'type': 'string'}, 'verification': {'type': 'string'}},
            'required': ['script', 'verification'],
        },
    },
}


class GenerationOutputError(ValueError):
    pass


def parse_script_response(content: str, finish_reason: str | None = None) -> Scripts:
    if finish_reason == 'length':
        raise GenerationOutputError('The model truncated the script draft. Request a smaller task; nothing was executed.')
    if finish_reason in {'content_filter', 'refusal'}:
        raise GenerationOutputError('The provider declined to generate this draft. Nothing was executed.')
    if not content.strip():
        raise GenerationOutputError('The provider returned an empty draft. Nothing was executed.')
    if len(content) > 80_000:
        raise GenerationOutputError('The generated draft exceeds the response limit. Nothing was executed.')
    content = content.strip()
    fenced = re.fullmatch(r'```(?:json)?\s*\n([\s\S]*?)\n```', content, re.IGNORECASE)
    if fenced:
        content = fenced.group(1)
    try:
        data = json.loads(content)
    except ValueError as error:
        raise GenerationOutputError('The provider returned malformed JSON instead of a script draft. Nothing was executed.') from error
    try:
        return Scripts.model_validate(data)
    except ValueError as error:
        raise GenerationOutputError('The generated draft failed Python syntax or script-field validation. Nothing was executed.') from error
