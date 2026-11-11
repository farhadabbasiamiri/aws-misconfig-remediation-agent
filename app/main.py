"""Gradio entry point.

Run: python app/main.py
"""

import os
import sys
from pathlib import Path

# Set before importing gradio: no reason for a security tool to phone home,
# and it removes an outbound network call from the startup path that has
# been observed to hang indefinitely rather than time out.
os.environ.setdefault("GRADIO_ANALYTICS_ENABLED", "False")

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
    # server_name="0.0.0.0": gradio defaults to 127.0.0.1, which is unreachable
    # from outside a Docker container even with the port published.
    demo.launch(show_api=False, server_name="0.0.0.0")


if __name__ == "__main__":
    main()
