"""Gradio entry point.

Run: python app/main.py
"""

import sys
from pathlib import Path

# Allow `python app/main.py` to find the app package without needing -m.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from app.ui.app import build_app  # noqa: E402


def main() -> None:
    demo = build_app()
    # show_api=False works around a gradio_client/pydantic schema-introspection
    # bug ("argument of type 'bool' is not iterable") triggered by dict[str, Any]
    # return types on some gradio 4.x + pydantic 2.x combinations; we don't need
    # the auto-generated REST API docs for this project anyway.
    demo.launch(show_api=False)


if __name__ == "__main__":
    main()
