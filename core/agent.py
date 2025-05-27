"""
CryptoAgent: primary AI planner/solver (OpenAI → Anthropic fallback).
"""
import os
import json
import logging
from langchain_openai               import ChatOpenAI
from langchain_community.chat_models import ChatAnthropic
from core.prompts                    import (
    STATE_ASSESSMENT_PROMPT,
    STRATEGY_SELECTION_PROMPT,
    DIRECT_SOLUTION_PROMPT
)

logger = logging.getLogger(__name__)

class CryptoAgent:
    def __init__(
        self,
        provider: str = "openai",
        api_key:  str = None,
        model:    str = None,
        verbose:  bool = False
    ):
        self.provider = provider
        self.api_key   = api_key or os.getenv("OPENAI_API_KEY")
        self.model     = model
        self.verbose   = verbose
        self.client    = self._init_client()
        self._tool_outputs = []

    def _init_client(self):
        # Try OpenAI first
        if self.provider in ("openai", None) and self.api_key:
            try:
                logger.info("🔗 Connecting to OpenAI…")
                return ChatOpenAI(
                    openai_api_key=self.api_key,
                    model_name=self.model or "gpt-4o-2024-05-13",
                    temperature=0.2,
                    max_tokens=4000
                )
            except Exception as e:
                logger.warning(f"OpenAI init failed: {e}")
        # Fallback Anthropic
        anth = os.getenv("ANTHROPIC_API_KEY")
        if anth:
            try:
                logger.info("🔗 Connecting to Anthropic…")
                return ChatAnthropic(
                    anthropic_api_key=anth,
                    model=self.model or "claude-3.5-sonnet",
                    max_tokens_to_sample=4000,
                    temperature=0.2
                )
            except Exception as e:
                logger.warning(f"Anthropic init failed: {e}")
        raise RuntimeError("No LLM provider available")

    def _call(self, prompt: str) -> str:
        try:
            r = self.client.chat.choices.create(
                messages=[{"role":"user","content":prompt}]
            )
            return r.choices[0].message.content
        except Exception as e:
            logger.error(f"LLM call error: {e}")
            return ""

    def assess_state(self, state) -> str:
        prompt = STATE_ASSESSMENT_PROMPT.format(state=state.get_summary())
        out = self._call(prompt).strip()
        return out or "No assessment available."

    def select_strategy(self, state, assessment: str) -> dict:
        findings = state.get_high_confidence_findings()
        finds_text = "\n".join(f"- {f.title}: {f.description}" for f in findings) or "None"
        prompt = STRATEGY_SELECTION_PROMPT.format(
            assessment=assessment,
            findings=finds_text
        )
        out = self._call(prompt)
        try:
            return json.loads(out)
        except Exception:
            pending = state.get_available_analyzers()
            return {"suggestions":[{"type":"run_analyzer","analyzer":a} for a in pending]}

    def attempt_direct(self, state) -> str:
        allf = state.get_all_findings()
        prompt = DIRECT_SOLUTION_PROMPT.format(
            findings="\n".join(f"- {f.description}" for f in allf)
        )
        out = self._call(prompt)
        if "SOLUTION:" in out:
            sol = out.split("SOLUTION:")[-1].strip()
            state.set_solution(sol)
            return sol
        return None

    def receive_tool_outputs(self, outputs: list):
        self._tool_outputs.extend(outputs)
        if self.verbose:
            logger.info(f"CryptoAgent received {len(outputs)} tool outputs")
