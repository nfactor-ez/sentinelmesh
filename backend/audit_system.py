"""
SentinelMesh — Audit Integrity System (Module 6)
Cryptographic SHA-256 hash-chain logging for tamper-proof audit trails.
Each entry links to the previous via hash, forming an immutable chain.
"""

import hashlib
import json
import threading
from datetime import datetime, timezone
from typing import Dict, List, Optional


class AuditChain:
    """Thread-safe SHA-256 hash chain for audit logging."""

    GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

    def __init__(self):
        self._entries: List[Dict] = []
        self._lock = threading.Lock()

    @property
    def entries(self) -> List[Dict]:
        with self._lock:
            return list(self._entries)

    @property
    def length(self) -> int:
        with self._lock:
            return len(self._entries)

    @staticmethod
    def _compute_hash(entry_id: int, timestamp: str, full_prompt_hash: str,
                      classification: str, risk_score: float, previous_hash: str) -> str:
        """Deterministic SHA-256 hash of an audit entry's fields."""
        payload = (
            str(entry_id)
            + timestamp
            + full_prompt_hash
            + classification
            + str(risk_score)
            + previous_hash
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def add_entry(self, firewall_result: dict) -> Dict:
        """
        Add a new entry to the audit chain from a firewall analysis result.
        Returns the new audit entry dict.
        """
        with self._lock:
            entry_id = len(self._entries) + 1
            timestamp = firewall_result.get("timestamp", datetime.now(timezone.utc).isoformat())
            prompt = firewall_result.get("prompt", "")
            prompt_preview = prompt[:50] + ("..." if len(prompt) > 50 else "")
            full_prompt_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
            classification = firewall_result.get("classification", "UNKNOWN")
            risk_score = firewall_result.get("risk_score", 0)

            # Previous hash: genesis for first entry, else last entry's hash
            previous_hash = (
                self.GENESIS_HASH if not self._entries
                else self._entries[-1]["entry_hash"]
            )

            entry_hash = self._compute_hash(
                entry_id, timestamp, full_prompt_hash,
                classification, risk_score, previous_hash,
            )

            entry = {
                "entry_id": entry_id,
                "timestamp": timestamp,
                "prompt_preview": prompt_preview,
                "full_prompt_hash": full_prompt_hash,
                "classification": classification,
                "risk_score": risk_score,
                "keyword_matches": firewall_result.get("keyword_matches", []),
                "blocked": firewall_result.get("blocked", False),
                "previous_hash": previous_hash,
                "entry_hash": entry_hash,
            }

            self._entries.append(entry)
            return entry

    def verify_chain(self) -> Dict:
        """
        Verify the integrity of the entire hash chain.
        Returns verification result with tampered_at info if any mismatch found.
        """
        with self._lock:
            if not self._entries:
                return {"valid": True, "tampered_at": None, "entries_checked": 0}

            for i, entry in enumerate(self._entries):
                # Check previous_hash link
                expected_prev = (
                    self.GENESIS_HASH if i == 0
                    else self._entries[i - 1]["entry_hash"]
                )
                if entry["previous_hash"] != expected_prev:
                    return {
                        "valid": False,
                        "tampered_at": entry["entry_id"],
                        "error": "previous_hash mismatch",
                        "entries_checked": i + 1,
                    }

                # Recompute entry hash and compare
                recomputed = self._compute_hash(
                    entry["entry_id"],
                    entry["timestamp"],
                    entry["full_prompt_hash"],
                    entry["classification"],
                    entry["risk_score"],
                    entry["previous_hash"],
                )
                if recomputed != entry["entry_hash"]:
                    return {
                        "valid": False,
                        "tampered_at": entry["entry_id"],
                        "error": "entry_hash mismatch",
                        "entries_checked": i + 1,
                    }

            return {
                "valid": True,
                "tampered_at": None,
                "entries_checked": len(self._entries),
            }

    def get_entries(self, limit: int = 50, offset: int = 0) -> List[Dict]:
        """Get paginated audit entries, newest first."""
        with self._lock:
            reversed_entries = list(reversed(self._entries))
            return reversed_entries[offset: offset + limit]

    def clear(self):
        """Reset the chain (for testing only)."""
        with self._lock:
            self._entries.clear()


# ── Global singleton ──
audit_chain = AuditChain()


# ── Self-test ──
if __name__ == "__main__":
    # Simulate adding entries
    sample_results = [
        {"prompt": "What is the capital of France?", "classification": "SAFE",
         "risk_score": 5.2, "keyword_matches": [], "blocked": False,
         "timestamp": "2025-01-01T12:00:00Z"},
        {"prompt": "How to hack into a bank system and steal money",
         "classification": "CRITICAL", "risk_score": 92.1,
         "keyword_matches": ["hack", "steal"], "blocked": True,
         "timestamp": "2025-01-01T12:00:02Z"},
        {"prompt": "Explain photosynthesis", "classification": "SAFE",
         "risk_score": 3.1, "keyword_matches": [], "blocked": False,
         "timestamp": "2025-01-01T12:00:04Z"},
    ]

    for r in sample_results:
        entry = audit_chain.add_entry(r)
        print(f"Entry #{entry['entry_id']}: {entry['entry_hash'][:16]}... | Prev: {entry['previous_hash'][:16]}...")

    result = audit_chain.verify_chain()
    print(f"\nChain verification: {result}")
