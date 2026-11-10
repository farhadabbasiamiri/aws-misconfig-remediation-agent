"""Workaround for a gradio_client schema-introspection bug.

gradio==4.44.1's File component produces a JSON schema containing a bare
boolean sub-schema (`"additionalProperties": true`, which is valid JSON
Schema shorthand for "any value"). gradio_client.utils._json_schema_to_python_type
assumes every schema node is a dict and crashes with
`TypeError: argument of type 'bool' is not iterable` the moment a page
with a File component loads -- this breaks the whole app, not just the
Export/Analyze tabs. There is no newer 4.x release that fixes it at the
time of writing, so this patches the one function to treat a bool schema
as "Any", exactly how the rest of that function already treats an empty
`{}` schema.

Call apply() once, before building the Blocks app.
"""

from gradio_client import utils as _gc_utils

_original_json_schema_to_python_type = _gc_utils._json_schema_to_python_type
_applied = False


def _patched_json_schema_to_python_type(schema, defs):
    if isinstance(schema, bool):
        return "Any"
    return _original_json_schema_to_python_type(schema, defs)


def apply() -> None:
    global _applied
    if _applied:
        return
    _gc_utils._json_schema_to_python_type = _patched_json_schema_to_python_type
    _applied = True
