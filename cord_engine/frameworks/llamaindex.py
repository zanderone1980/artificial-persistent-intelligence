"""CORD Framework Adapter — LlamaIndex (Python).

Wraps LlamaIndex LLM instances so every complete()/chat() call is
gated through CORD. If CORD blocks, a RuntimeError is raised.

Usage:
    from cord_engine.frameworks import wrap_llamaindex_llm

    llm = wrap_llamaindex_llm(OpenAI(), session_intent="RAG pipeline")
    llm.complete("Hello")  # CORD gated
"""

from __future__ import annotations

from typing import Any

from cord_engine import evaluate, Proposal, Decision


def _extract_messages_text(messages: Any) -> str:
    """Extract text from LlamaIndex ChatMessage list."""
    if isinstance(messages, str):
        return messages
    if isinstance(messages, (list, tuple)):
        parts = []
        for msg in messages:
            if isinstance(msg, str):
                parts.append(msg)
            elif hasattr(msg, "content"):
                parts.append(str(msg.content))
            else:
                parts.append(str(msg))
        return "\n".join(parts)
    return str(messages)


def wrap_llamaindex_llm(llm: Any, session_intent: str = "") -> Any:
    """Wrap a LlamaIndex LLM with CORD enforcement.

    Monkey-patches complete() and chat() so every call passes through
    CORD first.

    Args:
        llm: LlamaIndex LLM instance (OpenAI, Anthropic, HuggingFaceLLM, etc.)
        session_intent: Declared session goal.

    Returns:
        The same LLM instance with CORD-gated methods.
    """
    # Wrap complete()
    if hasattr(llm, "complete") and callable(llm.complete):
        original_complete = llm.complete

        def guarded_complete(prompt: Any, *args: Any, **kwargs: Any) -> Any:
            text = prompt if isinstance(prompt, str) else str(prompt)
            verdict = evaluate(Proposal(
                text=text,
                session_intent=session_intent,
            ))
            if verdict.decision == Decision.BLOCK:
                raise RuntimeError(
                    f"CORD BLOCK: {', '.join(verdict.reasons)}"
                )
            return original_complete(prompt, *args, **kwargs)

        llm.complete = guarded_complete

    # Wrap chat()
    if hasattr(llm, "chat") and callable(llm.chat):
        original_chat = llm.chat

        def guarded_chat(messages: Any, *args: Any, **kwargs: Any) -> Any:
            text = _extract_messages_text(messages)
            verdict = evaluate(Proposal(
                text=text,
                session_intent=session_intent,
            ))
            if verdict.decision == Decision.BLOCK:
                raise RuntimeError(
                    f"CORD BLOCK: {', '.join(verdict.reasons)}"
                )
            return original_chat(messages, *args, **kwargs)

        llm.chat = guarded_chat

    # Wrap acomplete() (async variant)
    if hasattr(llm, "acomplete") and callable(llm.acomplete):
        original_acomplete = llm.acomplete

        async def guarded_acomplete(prompt: Any, *args: Any, **kwargs: Any) -> Any:
            text = prompt if isinstance(prompt, str) else str(prompt)
            verdict = evaluate(Proposal(
                text=text,
                session_intent=session_intent,
            ))
            if verdict.decision == Decision.BLOCK:
                raise RuntimeError(
                    f"CORD BLOCK: {', '.join(verdict.reasons)}"
                )
            return await original_acomplete(prompt, *args, **kwargs)

        llm.acomplete = guarded_acomplete

    # Wrap achat() (async variant)
    if hasattr(llm, "achat") and callable(llm.achat):
        original_achat = llm.achat

        async def guarded_achat(messages: Any, *args: Any, **kwargs: Any) -> Any:
            text = _extract_messages_text(messages)
            verdict = evaluate(Proposal(
                text=text,
                session_intent=session_intent,
            ))
            if verdict.decision == Decision.BLOCK:
                raise RuntimeError(
                    f"CORD BLOCK: {', '.join(verdict.reasons)}"
                )
            return await original_achat(messages, *args, **kwargs)

        llm.achat = guarded_achat

    return llm
