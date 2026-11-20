"""LLM provider abstraction. Providers return text; callers parse/validate JSON.

provider = none      -> no LLM; agents use deterministic fallbacks (core scanner is fully functional)
provider = anthropic -> Claude via the official `anthropic` SDK (default model claude-opus-5-5)
provider = openai    -> OpenAI via the official `openai` SDK
provider = fake      -> deterministic canned JSON (tests / demos without API keys)
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass

from ..config import get_settings

log = logging.getLogger("pipelinetrust.llm")


class LLMError(Exception):
    pass


@dataclass
class LLMResponse:
    text: str
    model: str
    provider: str


class LLMProvider:
    name = "none"
    model = ""

    @property
    def available(self) -> bool:
        return False

    def complete(self, system: str, prompt: str, max_tokens: int = 8000) -> LLMResponse:  # pragma: no cover
        raise LLMError("no LLM provider configured")


class AnthropicProvider(LLMProvider):
    name = "anthropic"

    def __init__(self, api_key: str, model: str, timeout: int):
        import anthropic

        self._anthropic = anthropic
        self.client = anthropic.Anthropic(api_key=api_key or None, timeout=float(timeout), max_retries=2)
        self.model = model or "claude-opus-5-5"

    @property
    def available(self) -> bool:
        return True

    def complete(self, system: str, prompt: str, max_tokens: int = 8000) -> LLMResponse:
        a = self._anthropic
        kwargs = dict(model=self.model, max_tokens=max_tokens, system=system,
                      messages=[{"role": "user", "content": prompt}], output_config={"effort": "medium"})
        try:
            try:
                # Server-side refusal fallback (routes a policy decline to another model inside the same call).
                resp = self.client.beta.messages.create(betas=["server-side-fallback-2026-07-01"], fallbacks="default", **kwargs)
            except TypeError:  # SDK without the `fallbacks` parameter
                resp = self.client.messages.create(**kwargs)
        except a.AuthenticationError as exc:
            raise LLMError("Anthropic authentication failed (check PT_ANTHROPIC_API_KEY)") from exc
        except a.RateLimitError as exc:
            raise LLMError("Anthropic rate limit exceeded") from exc
        except a.APIStatusError as exc:
            raise LLMError(f"Anthropic API error {exc.status_code}") from exc
        except a.APIConnectionError as exc:
            raise LLMError("cannot reach Anthropic API") from exc
        if resp.stop_reason == "refusal":
            raise LLMError("model declined the request")
        text = "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")
        return LLMResponse(text=text, model=resp.model, provider=self.name)


class OpenAIProvider(LLMProvider):
    name = "openai"

    def __init__(self, api_key: str, model: str, timeout: int):
        import openai

        self._openai = openai
        self.client = openai.OpenAI(api_key=api_key or None, timeout=float(timeout), max_retries=2)
        self.model = model or "gpt-4.1"

    @property
    def available(self) -> bool:
        return True

    def complete(self, system: str, prompt: str, max_tokens: int = 8000) -> LLMResponse:
        o = self._openai
        try:
            resp = self.client.chat.completions.create(
                model=self.model, max_completion_tokens=max_tokens, response_format={"type": "json_object"},
                messages=[{"role": "system", "content": system}, {"role": "user", "content": prompt}])
        except o.AuthenticationError as exc:
            raise LLMError("OpenAI authentication failed (check PT_OPENAI_API_KEY)") from exc
        except o.APIError as exc:
            raise LLMError(f"OpenAI API error: {type(exc).__name__}") from exc
        return LLMResponse(text=resp.choices[0].message.content or "", model=resp.model, provider=self.name)


class FakeProvider(LLMProvider):
    """Deterministic provider for tests: echoes back structured JSON derived from the prompt's data block,
    and deliberately includes one hallucinated finding id so guardrails can be verified."""
    name = "fake"
    model = "fake-model"

    @property
    def available(self) -> bool:
        return True

    def complete(self, system: str, prompt: str, max_tokens: int = 8000) -> LLMResponse:
        data = extract_json(prompt.split("DATA:", 1)[-1]) or {}
        task = data.get("task", "")
        if task == "context":
            out = {"summary": f"Repository with {len(data.get('workflows', []))} workflow(s).", "deployment_targets": ["(fake)"],
                   "crown_jewels": ["release pipeline"], "trust_boundaries": ["fork pull requests"]}
        elif task == "triage":
            items = [{"finding_id": f["id"], "exploitability": "likely" if f["severity"] in ("critical", "high") else "possible",
                      "rationale": "fake rationale", "priority": "P1" if f["severity"] == "critical" else "P2",
                      "false_positive_likelihood": "low"} for f in data.get("findings", [])]
            items.append({"finding_id": "HALLUCINATED-ID", "exploitability": "likely", "rationale": "x", "priority": "P1",
                          "false_positive_likelihood": "low"})
            out = {"assessments": items}
        elif task == "attack_paths":
            out = {"narratives": [{"path_id": p["id"], "narrative": f"Fake narrative for {p['id']}", "break_point": "fake"}
                                  for p in data.get("paths", [])] + [{"path_id": "AP-99", "narrative": "invented", "break_point": "x"}]}
        elif task == "remediation":
            out = {"fixes": [{"finding_id": f["id"], "explanation": "fake fix", "patch": "permissions:\n  contents: read"}
                             for f in data.get("findings", [])]}
        elif task == "ask":
            fs = data.get("findings") or []
            real = f"[F:{fs[0]['id']}]" if fs else ""
            out = {"answer": f"Fake answer citing {real} and an invented finding [F:HALLUCINATED-ID] and [AP:AP-99]."}
        elif task == "policy":
            pid = data.get("suggested_id", "ORG-AI-0001")
            out = {"yaml": "\n".join([f"id: {pid}", "title: Fake drafted policy", "severity: high", "category: CICD-SEC-7", "target: job",
                                      "when:", "  - {field: self_hosted, equals: true}", 'message: "Job {id} uses a self-hosted runner"', ""]),
                   "explanation": "fake explanation"}
        elif task == "summary":
            out = {"executive_summary": "Fake executive summary.", "top_risks": ["fake risk"], "recommended_actions": ["fake action"]}
        else:
            out = {}
        return LLMResponse(text="```json\n" + json.dumps(out) + "\n```", model=self.model, provider=self.name)


def extract_json(text: str):
    """Pull the first JSON object out of model text (tolerates code fences / prose)."""
    if not text:
        return None
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    candidates = [m.group(1)] if m else []
    start = text.find("{")
    if start >= 0:
        depth = 0
        for i in range(start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    candidates.append(text[start:i + 1])
                    break
    for c in candidates:
        try:
            return json.loads(c)
        except json.JSONDecodeError:
            continue
    return None


def get_provider(name: str | None = None) -> LLMProvider:
    s = get_settings()
    name = (name or s.llm_provider or "none").lower()
    try:
        if name == "anthropic" and s.anthropic_api_key:
            return AnthropicProvider(s.anthropic_api_key, s.llm_model, s.llm_timeout_seconds)
        if name == "openai" and s.openai_api_key:
            return OpenAIProvider(s.openai_api_key, s.llm_model, s.llm_timeout_seconds)
        if name == "fake":
            return FakeProvider()
    except ImportError as exc:
        log.warning("LLM SDK missing: %s", exc)
    return LLMProvider()
