import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import yaml


@dataclass
class PolicyDecision:
    decision: str
    reason: str
    conditions: Dict[str, Any]


class PolicyEngine:
    """
    Lightweight policy-as-code evaluator using a YAML DSL.
    Decision outcomes:
      - permit
      - deny
      - permit_with_conditions
    """

    def __init__(self, policy_path: str):
        self.policy_path = policy_path
        self.policy: Dict[str, Any] = {}
        self.reload()

    def reload(self) -> None:
        if not os.path.isfile(self.policy_path):
            self.policy = {}
            return
        with open(self.policy_path, "r", encoding="utf-8") as f:
            self.policy = yaml.safe_load(f) or {}

    def current(self) -> Dict[str, Any]:
        return self.policy or {}

    def evaluate(
        self,
        action: str,
        environment: str = "lab",
        role: Optional[str] = None,
        risk: float = 0.0,
        tool: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> PolicyDecision:
        p = self.policy or {}
        md = metadata or {}
        env = (environment or "lab").lower()
        role = role or "Analyst"

        # 1) Hard deny rules
        for rule in p.get("deny_rules", []) or []:
            r_action = str(rule.get("action", "")).strip()
            r_envs = [str(x).lower() for x in (rule.get("environments") or [])]
            if r_action == action and (not r_envs or env in r_envs):
                return PolicyDecision("deny", str(rule.get("reason", "Denied by policy")), {})

        # 2) Tool allow-list
        allow_tools = p.get("allow_tools") or []
        if tool and allow_tools and tool not in allow_tools:
            return PolicyDecision("deny", f"Tool not allowed: {tool}", {})

        # 3) Red team restricted to lab
        if action.startswith("redteam.") and env != "lab":
            return PolicyDecision("deny", "Red team actions are lab-only", {})

        # 4) Approval matrix for high-impact actions
        approvals = p.get("approvals") or {}
        req = approvals.get(action)
        if isinstance(req, dict):
            required_role = str(req.get("required_role", "")).strip()
            if required_role and role != required_role:
                return PolicyDecision(
                    "permit_with_conditions",
                    "Missing required approval role",
                    {"required_role": required_role, "current_role": role},
                )

        # 5) Risk-based conditions
        high_risk = float(p.get("high_risk_threshold", 0.8))
        if risk >= high_risk:
            gate_role = str(p.get("high_risk_required_role", "IR-Lead"))
            if role != gate_role:
                return PolicyDecision(
                    "permit_with_conditions",
                    "High-risk action requires elevated role",
                    {"required_role": gate_role, "current_role": role, "risk": risk},
                )

        # 6) Optional metadata checks
        forbidden_targets = [str(x).lower() for x in (p.get("forbidden_targets") or [])]
        target = str(md.get("target", "")).lower()
        if target and target in forbidden_targets:
            return PolicyDecision("deny", f"Target forbidden by policy: {target}", {})

        return PolicyDecision("permit", "Policy permit", {})
