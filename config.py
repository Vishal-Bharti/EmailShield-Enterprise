import os
from typing import Optional

import streamlit as st


def get_secret(name: str, default: Optional[str] = None) -> Optional[str]:
    try:
        value = st.secrets.get(name)
        if value:
            return str(value)
    except Exception:
        pass

    value = os.getenv(name)
    if value:
        return str(value)

    return default


def mask_secret(value: Optional[str]) -> str:
    if not value:
        return "Not configured"
    if len(value) <= 4:
        return "*" * len(value)
    return f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}"
