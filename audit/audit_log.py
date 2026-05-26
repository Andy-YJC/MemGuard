"""
Structured JSON audit logger for memguard.

Every intercepted, quarantined, or state-changed MemoryEntry emits a
one-line JSON record to both stderr (via stdlib logging) and an optional
JSONL file, making the audit trail machine-readable and grep-friendly.

When a public key is supplied at construction, each record also includes
Ed25519 signature verification and audit-chain integrity status, bridging
the cryptographic signing layer with the persistent audit trail.
"""

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ..models.memory_entry import AuditEvent, MemoryEntry

_LOGGER = logging.getLogger("memguard.audit")


def _configure_logger(log_file: Optional[Path]) -> None:
    if _LOGGER.handlers:
        return  # already configured
    fmt = logging.Formatter("%(message)s")

    sh = logging.StreamHandler(sys.stderr)
    sh.setFormatter(fmt)
    _LOGGER.addHandler(sh)

    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setFormatter(fmt)
        _LOGGER.addHandler(fh)

    _LOGGER.setLevel(logging.INFO)
    _LOGGER.propagate = False


class StructuredAuditLogger:
    """
    Writes one JSON line per audit event to stderr and (optionally) a JSONL file.

    Each record contains enough context to reconstruct what happened to a
    MemoryEntry without having to load the full entry from the vector DB.

    When ``public_key`` is provided, ``log_event()`` and ``log_write()``
    also verify the entry's Ed25519 signature and append-only audit hash
    chain, including ``sig_verified`` and ``chain_integrity`` fields in
    the emitted record.
    """

    def __init__(
        self,
        log_file: Optional[Path] = None,
        public_key: Optional[Ed25519PublicKey] = None,
    ):
        _configure_logger(log_file)
        self._public_key = public_key

    # ── Public API ────────────────────────────────────────────────────────────

    def log_event(self, entry: MemoryEntry, event: AuditEvent) -> None:
        """Emit a structured record for a state-change event on an entry.

        Includes audit-chain context (``event_id``, ``previous_event_hash``,
        ``audit_trail_length``).  If a ``public_key`` was provided, also
        includes ``sig_verified`` and ``chain_integrity``.
        """
        record: dict = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "entry_id": entry.entry_id,
            "source_id": entry.source_id,
            "source_type": entry.source_type.value,
            "event_type": event.event_type.value,
            "event_id": event.event_id,
            "previous_event_hash": event.previous_event_hash,
            "audit_trail_length": len(entry.audit_trail),
            "actor": event.actor,
            "detail": event.detail,
            "event_metadata": event.metadata,
            "is_unsafe": entry.is_unsafe,
            "trust_score": entry.trust_score,
        }
        if self._public_key is not None:
            sig_ok = entry.verify_signature(self._public_key)
            chain_ok = entry.verify_audit_chain()
            record["sig_verified"] = sig_ok
            record["chain_integrity"] = chain_ok
        _LOGGER.info(json.dumps(record, ensure_ascii=False))

    def log_chain_integrity(
        self, entry: MemoryEntry, actor: str
    ) -> None:
        """Emit a standalone audit-chain integrity check for an entry.

        Does not log a state-change event; useful for periodic or
        on-demand verification of the hash chain and signature.
        """
        chain_ok = entry.verify_audit_chain()
        sig_ok: Optional[bool] = None
        if self._public_key is not None:
            sig_ok = entry.verify_signature(self._public_key)
        record: dict = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "action": "CHAIN_VERIFICATION",
            "entry_id": entry.entry_id,
            "audit_trail_length": len(entry.audit_trail),
            "chain_integrity": chain_ok,
            "sig_verified": sig_ok,
            "actor": actor,
        }
        _LOGGER.info(json.dumps(record, ensure_ascii=False))

    def log_interception(
        self,
        entry_id: str,
        source_id: str,
        action: str,
        reason: str,
        actor: str,
        extra: Optional[dict] = None,
    ) -> None:
        """Emit a record for a gateway-level interception (before entry is created)."""
        record: dict = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "entry_id": entry_id,
            "source_id": source_id,
            "action": action,
            "reason": reason,
            "actor": actor,
        }
        if extra:
            record.update(extra)
        _LOGGER.info(json.dumps(record, ensure_ascii=False))

    def log_write(self, entry: MemoryEntry, actor: str) -> None:
        """Convenience: log a successful memory write operation."""
        sig_ok: Optional[bool] = None
        chain_ok: Optional[bool] = None
        if self._public_key is not None:
            sig_ok = entry.verify_signature(self._public_key)
            chain_ok = entry.verify_audit_chain()
        record: dict = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "action": "MEMORY_WRITE",
            "entry_id": entry.entry_id,
            "source_id": entry.source_id,
            "source_type": entry.source_type.value,
            "session_hash": entry.session_hash,
            "trust_score": entry.trust_score,
            "sig_present": bool(entry.cryptographic_sig),
            "sig_verified": sig_ok,
            "chain_integrity": chain_ok,
            "actor": actor,
        }
        _LOGGER.info(json.dumps(record, ensure_ascii=False))

    def log_read(
        self, entry_id: str, actor: str, blocked: bool, reason: str = ""
    ) -> None:
        """Convenience: log a memory read/retrieval attempt."""
        record: dict = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "action": "MEMORY_READ",
            "entry_id": entry_id,
            "actor": actor,
            "blocked": blocked,
            "reason": reason,
        }
        _LOGGER.info(json.dumps(record, ensure_ascii=False))
