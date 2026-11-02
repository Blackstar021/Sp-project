"""Vercel entry point for the CyberSafe Flask app.

Vercel's Python runtime looks for a module-level WSGI application named
``app``. The Flask project lives in the ``CyberSafe`` subdirectory, so we add
that folder to ``sys.path`` before importing it.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "CyberSafe"))

from app import app  # noqa: E402,F401
