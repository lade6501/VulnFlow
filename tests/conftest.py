"""
tests/conftest.py
Disables live telemetry and persistence before pytest imports the application.
"""

import os


# A workstation's .env must not start a live tracing worker or select remote storage.
os.environ["LANGCHAIN_TRACING_V2"] = "false"
os.environ["SUPABASE_URL"] = ""
os.environ["VULNFLOW_SUPABASE_REQUIRED"] = "false"
