import json
import re
from typing import Any, Dict, List, Optional


_DEFAULT_INJECTION_PATTERNS = [
    r"ignore\s+previous\s+instructions",
    r"system\s+prompt",
    r"developer\s+message",
    r"bypass\s+safety",
    r"jailbreak",
    r"exfiltrat(e|ion)",
    r"prompt\s+injection",
    r"BEGIN\s+SYSTEM\s+PROMPT",
]

_DEFAULT_EXFIL_PATTERNS = [
    r"api[_-]?key",
    r"secret",
    r"token",
    r"password",
    r"private\s+key",
]

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class AIFirewall:
    def __init__(self, max_chars: int = 8000):
        self.max_chars = max_chars
        self.injection_patterns = [re.compile(p, re.IGNORECASE) for p in _DEFAULT_INJECTION_PATTERNS]
        self.exfil_patterns = [re.compile(p, re.IGNORECASE) for p in _DEFAULT_EXFIL_PATTERNS]

    def _score(self, hits: int, denom: int = 3) -> float:
        if hits <= 0:
            return 0.0
        return min(float(hits) / float(max(denom, 1)), 1.0)

    def _text(self, payload: Any) -> str:
        if payload is None:
            return ""
        if isinstance(payload, str):
            return payload
        try:
            return json.dumps(payload, ensure_ascii=False, default=str)
        except Exception:
            return str(payload)

    def precheck(self, text: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        txt = self._text(text)
        ctx = context or {}
        reasons: List[str] = []

        if len(txt) > self.max_chars:
            reasons.append("text_too_large")

        inj_hits = sum(1 for p in self.injection_patterns if p.search(txt))
        exfil_hits = sum(1 for p in self.exfil_patterns if p.search(txt))
        pii_hits = int(bool(_EMAIL_RE.search(txt))) + int(bool(_SSN_RE.search(txt)))

        jailbreak_score = self._score(inj_hits, 2)
        exfil_score = self._score(exfil_hits + pii_hits, 3)

        if inj_hits > 0:
            reasons.append("prompt_injection_signals")
        if pii_hits > 0:
            reasons.append("pii_detected")
        if exfil_hits > 0:
            reasons.append("secret_exfil_signals")

        blocked = bool(
            "text_too_large" in reasons
            or jailbreak_score >= 0.8
            or exfil_score >= 0.8
            or ctx.get("strict_mode") is True and (inj_hits > 0 or pii_hits > 0)
        )

        return {
            "blocked": blocked,
            "jailbreak_score": jailbreak_score,
            "exfil_score": exfil_score,
            "reasons": reasons,
        }

    def postcheck(self, output: Any, required_keys: Optional[List[str]] = None) -> Dict[str, Any]:
        txt = self._text(output)
        reasons: List[str] = []
        data = output

        if required_keys:
            if not isinstance(output, dict):
                reasons.append("output_not_json_object")
            else:
                missing = [k for k in required_keys if k not in output]
                if missing:
                    reasons.append(f"missing_required_keys:{','.join(missing)}")

        pii_found = bool(_EMAIL_RE.search(txt) or _SSN_RE.search(txt))
        if pii_found:
            reasons.append("pii_detected")

        exploit_signals = bool(re.search(r"(reverse\s+shell|rm\s+-rf|powershell\s+-enc)", txt, re.IGNORECASE))
        if exploit_signals:
            reasons.append("unsafe_exploit_output")

        blocked = bool("output_not_json_object" in reasons or exploit_signals)

        # simple redaction for PII
        redacted = txt
        redacted = _EMAIL_RE.sub("[REDACTED_EMAIL]", redacted)
        redacted = _SSN_RE.sub("[REDACTED_SSN]", redacted)
        redacted = _IP_RE.sub("[REDACTED_IP]", redacted)

        if isinstance(data, str):
            data_out: Any = redacted
        else:
            data_out = output

        return {"blocked": blocked, "reasons": reasons, "redacted_output": data_out}

    def scan_provenance_doc(self, content: str) -> Dict[str, Any]:
        txt = self._text(content)
        suspect = []
        if re.search(r"ignore\s+all\s+previous\s+instructions", txt, re.IGNORECASE):
            suspect.append("indirect_injection")
        if re.search(r"BEGIN\s+SYSTEM\s+PROMPT|END\s+SYSTEM\s+PROMPT", txt, re.IGNORECASE):
            suspect.append("system_prompt_markers")
        if re.search(r"(curl\s+http|wget\s+http|powershell\s+-enc)", txt, re.IGNORECASE):
            suspect.append("executable_payload_hint")
        return {"safe": len(suspect) == 0, "signals": suspect}
