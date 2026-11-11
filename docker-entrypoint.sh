#!/bin/sh
set -e

CHROMA_DIR="${CHROMA_PATH:-kb/chroma}"
if [ ! -d "$CHROMA_DIR" ] || [ -z "$(ls -A "$CHROMA_DIR" 2>/dev/null)" ]; then
  echo "Chroma knowledge base not found at $CHROMA_DIR -- building it..."
  python kb/ingest.py
fi

exec python app/main.py
