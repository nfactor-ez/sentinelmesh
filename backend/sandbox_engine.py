"""Layer 8 — Sandbox isolation decision engine."""

from typing import Dict, List


def run_sandbox_decision(policy: Dict, layer_outputs: List[Dict]) -> Dict:
    action = policy.get("enforcement_action", "ALLOW")
    total_risk = sum(l.get("risk_contribution", 0) for l in layer_outputs)

    decisions = {
        "ALLOW": {
            "state": "ALLOW",
            "docker": "standard-isolation",
            "gvisor": "sentry-active",
            "filesystem": "read-only-root",
            "network": "egress-filtered",
            "capabilities": "dropped",
        },
        "RESTRICTED_EXECUTION": {
            "state": "RESTRICTED EXECUTION",
            "docker": "no-new-privileges",
            "gvisor": "strict-seccomp",
            "filesystem": "read-only-root",
            "network": "deny-egress",
            "capabilities": "minimal",
        },
        "QUARANTINE": {
            "state": "QUARANTINE",
            "docker": "isolated-namespace",
            "gvisor": "panic-on-syscall-violation",
            "filesystem": "tmpfs-only",
            "network": "isolated",
            "capabilities": "none",
        },
        "BLOCK": {
            "state": "BLOCKED",
            "docker": "execution-halted",
            "gvisor": "sandbox-sealed",
            "filesystem": "no-mount",
            "network": "disabled",
            "capabilities": "none",
        },
    }
    cfg = decisions.get(action, decisions["BLOCK"])

    return {
        "layer": "sandbox_decision",
        "passed": action == "ALLOW",
        "risk_contribution": 0.0,
        "sandbox_decision": cfg["state"],
        "isolation": cfg,
        "integrity": "MAINTAINED" if action != "BLOCK" else "SEALED",
        "blocked": action in ("BLOCK", "QUARANTINE"),
    }
