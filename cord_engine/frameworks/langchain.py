"""CORD Framework Adapter — LangChain (Python).

Provides two integration patterns:

1. CORDCallbackHandler — LangChain callback that gates every
   LLM and tool call through CORD. Attach to any chain/agent.

2. wrap_langchain_llm() — Monkey-patches invoke() on an LLM
   instance to run CORD before every call.

Usage (callback):
    from cord_engine.frameworks import CORDCallbackHandler

    handler = CORDCallbackHandler(session_intent="Build a dashboard")
    chain.invoke(input, config={"callbacks": [handler]})

Usage (wrapper):
    from cord_engine.frameworks import wrap_langchain_llm

    llm = wrap_langchain_llm(ChatOpenAI(), session_intent="Build a dashboard")
    llm.invoke("Hello")  # CORD gated
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Union

from cord_engine import evaluate, Proposal, Decision


class CORDCallbackHandler:
    """LangChain callback handler that gates every LLM/tool call through CORD.

    Raises RuntimeError on BLOCK decisions. Compatible with LangChain's
    BaseCallbackHandler interface (duck-typed to avoid hard dependency).
    """

    def __init__(
        self,
        session_intent: str = "",
        throw_on_block: bool = True,
    ) -> None:
        self.session_intent = session_intent
        self.throw_on_block = throw_on_block

    def on_llm_start(
        self,
        serialized: Dict[str, Any],
        prompts: List[str],
        **kwargs: Any,
    ) -> None:
        """Gate LLM calls through CORD."""
        text = "\n".join(prompts)
        verdict = evaluate(Proposal(
            text=text,
            session_intent=self.session_intent,
        ))
        if verdict.decision == Decision.BLOCK and self.throw_on_block:
            raise RuntimeError(
                f"CORD BLOCK: {', '.join(verdict.reasons)}"
            )

    def on_chat_model_start(
        self,
        serialized: Dict[str, Any],
        messages: List[List[Any]],
        **kwargs: Any,
    ) -> None:
        """Gate chat model calls through CORD."""
        parts: list[str] = []
        for msg_list in messages:
            for msg in msg_list:
                content = getattr(msg, "content", str(msg))
                parts.append(content if isinstance(content, str) else str(content))
        text = "\n".join(parts)
        verdict = evaluate(Proposal(
            text=text,
            session_intent=self.session_intent,
        ))
        if verdict.decision == Decision.BLOCK and self.throw_on_block:
            raise RuntimeError(
                f"CORD BLOCK: {', '.join(verdict.reasons)}"
            )

    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        """Gate tool calls through CORD."""
        tool_name = serialized.get("name", "unknown")
        verdict = evaluate(Proposal(
            text=input_str,
            session_intent=self.session_intent,
        ))
        if verdict.decision == Decision.BLOCK and self.throw_on_block:
            raise RuntimeError(
                f"CORD BLOCK on tool {tool_name}: {', '.join(verdict.reasons)}"
            )

    # LangChain expects these to exist even if they're no-ops
    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        pass

    def on_llm_error(self, error: BaseException, **kwargs: Any) -> None:
        pass

    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        pass

    def on_tool_error(self, error: BaseException, **kwargs: Any) -> None:
        pass

    def on_chain_start(
        self,
        serialized: Dict[str, Any],
        inputs: Dict[str, Any],
        **kwargs: Any,
    ) -> None:
        pass

    def on_chain_end(self, outputs: Dict[str, Any], **kwargs: Any) -> None:
        pass

    def on_chain_error(self, error: BaseException, **kwargs: Any) -> None:
        pass


def wrap_langchain_llm(llm: Any, session_intent: str = "") -> Any:
    """Wrap a LangChain LLM with CORD enforcement.

    Monkey-patches invoke() so every call passes through CORD first.

    Args:
        llm: LangChain LLM instance (ChatOpenAI, ChatAnthropic, etc.)
        session_intent: Declared session goal for intent drift detection.

    Returns:
        The same LLM instance with CORD-gated invoke().
    """
    original_invoke = llm.invoke

    def guarded_invoke(
        input: Any,
        config: Any = None,
        **kwargs: Any,
    ) -> Any:
        text = input if isinstance(input, str) else str(input)
        verdict = evaluate(Proposal(
            text=text,
            session_intent=session_intent,
        ))
        if verdict.decision == Decision.BLOCK:
            raise RuntimeError(
                f"CORD BLOCK: {', '.join(verdict.reasons)}"
            )
        return original_invoke(input, config=config, **kwargs)

    llm.invoke = guarded_invoke
    return llm
