"""CORD Framework Adapters — Python.

Drop-in wrappers for LangChain, CrewAI, and LlamaIndex.
Every call to the wrapped model/agent/tool is gated through CORD
before execution. If CORD blocks, a RuntimeError is raised.

Usage:
    from cord_engine.frameworks import (
        CORDCallbackHandler,       # LangChain callback
        wrap_langchain_llm,        # LangChain LLM wrapper
        wrap_crewai_agent,         # CrewAI agent wrapper
        wrap_llamaindex_llm,       # LlamaIndex LLM wrapper
    )
"""

from .langchain import CORDCallbackHandler, wrap_langchain_llm
from .crewai import wrap_crewai_agent
from .llamaindex import wrap_llamaindex_llm

__all__ = [
    "CORDCallbackHandler",
    "wrap_langchain_llm",
    "wrap_crewai_agent",
    "wrap_llamaindex_llm",
]
