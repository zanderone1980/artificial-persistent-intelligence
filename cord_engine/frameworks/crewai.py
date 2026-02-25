"""CORD Framework Adapter — CrewAI (Python).

Wraps CrewAI agent instances so every execute() call is gated
through CORD. If CORD blocks, a RuntimeError is raised.

Usage:
    from cord_engine.frameworks import wrap_crewai_agent

    agent = wrap_crewai_agent(my_agent, session_intent="Research task")
    agent.execute(task)  # CORD gated
"""

from __future__ import annotations

from typing import Any

from cord_engine import evaluate, Proposal, Decision


def _extract_task_text(task: Any) -> str:
    """Extract text from a CrewAI task object or string."""
    if isinstance(task, str):
        return task
    if hasattr(task, "description"):
        text = task.description or ""
        if hasattr(task, "expected_output") and task.expected_output:
            text += f"\n{task.expected_output}"
        return text
    return str(task)


def wrap_crewai_agent(agent: Any, session_intent: str = "") -> Any:
    """Wrap a CrewAI Agent with CORD enforcement.

    Monkey-patches execute() so every task is evaluated by CORD first.

    Args:
        agent: CrewAI Agent instance.
        session_intent: Declared session goal.

    Returns:
        The same agent with CORD-gated execute().
    """
    if hasattr(agent, "execute") and callable(agent.execute):
        original_execute = agent.execute

        def guarded_execute(task: Any, *args: Any, **kwargs: Any) -> Any:
            text = _extract_task_text(task)
            verdict = evaluate(Proposal(
                text=text,
                session_intent=session_intent,
            ))
            if verdict.decision == Decision.BLOCK:
                raise RuntimeError(
                    f"CORD BLOCK: {', '.join(verdict.reasons)}"
                )
            return original_execute(task, *args, **kwargs)

        agent.execute = guarded_execute

    if hasattr(agent, "execute_task") and callable(agent.execute_task):
        original_execute_task = agent.execute_task

        def guarded_execute_task(
            task: Any,
            context: Any = None,
            tools: Any = None,
            **kwargs: Any,
        ) -> Any:
            text = _extract_task_text(task)
            verdict = evaluate(Proposal(
                text=text,
                session_intent=session_intent,
            ))
            if verdict.decision == Decision.BLOCK:
                raise RuntimeError(
                    f"CORD BLOCK: {', '.join(verdict.reasons)}"
                )
            return original_execute_task(task, context=context, tools=tools, **kwargs)

        agent.execute_task = guarded_execute_task

    return agent
