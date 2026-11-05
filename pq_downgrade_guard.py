#!/usr/bin/env python3
"""
pq_downgrade_guard.py: post-quantum TLS downgrade detector.

Runs with Python 3 only. No packages or network needed.

A hybrid TLS 1.3 handshake (X25519MLKEM768) sends an ML-KEM-768 key and an
X25519 key together. If an attacker removes the ML-KEM part, the session is
protected by X25519 alone, which a future quantum computer could break. The
attacker can record the traffic now and decrypt it later. TLS 1.3 signs the
handshake, so this needs a TLS-terminating proxy the attacker controls (or a
misconfigured endpoint); a plain eavesdropper can't edit it unnoticed.

This script flags a session when:
  1. it uses a classical-only group (X25519 or secp256r1) while post-quantum
     protection is required, or
  2. it claims the hybrid group but its key share is shorter than 1216 bytes,
     so the ML-KEM key is missing.
Flagged source addresses are quarantined.

Where it runs: on a TLS gateway in front of command-and-control services. It
reads handshake metadata only, not session contents.

Values used:
  * X25519MLKEM768 = 0x11EC, X25519 = 0x001D, secp256r1 = 0x0017
    (IANA TLS Supported Groups registry).
  * ML-KEM-768 encapsulation key = 1184 bytes (NIST FIPS 203). X25519 key =
    32 bytes. Hybrid client share = 1216 bytes.
ML-KEM is not broken. This detects ML-KEM being removed from the handshake.

Limits:
  * A real tool would parse TLS records and compare ServerHello with the
    groups the client offered, rather than read a prepared summary.
  * An attacker could pad the share to the right length, so a real tool would
    also check the key's structure.
  * Quarantine by IP address is coarse. A real tool would use client identity
    and a policy engine.
"""

import time
from dataclasses import dataclass, field
from typing import Any, Dict, Set

# IANA TLS Supported Groups codepoints
HYBRID_X25519_MLKEM768 = 0x11EC  # X25519MLKEM768 (hybrid PQ + classical)
CLASSICAL_X25519 = 0x001D        # Curve25519 (classical only)
CLASSICAL_SECP256R1 = 0x0017     # NIST P-256 (classical only)

GROUP_NAMES = {
    HYBRID_X25519_MLKEM768: "X25519MLKEM768",
    CLASSICAL_X25519: "X25519",
    CLASSICAL_SECP256R1: "secp256r1",
}

# Expected wire lengths (bytes)
MLKEM768_ENCAP_KEY_LEN = 1184      # FIPS 203 ML-KEM-768 encapsulation key
X25519_SHARE_LEN = 32              # X25519 public key
EXPECTED_HYBRID_SHARE_LEN = MLKEM768_ENCAP_KEY_LEN + X25519_SHARE_LEN  # 1216


@dataclass
class SessionTelemetry:
    """One observed TLS 1.3 handshake, reduced to the fields we police."""
    session_id: str
    client_ip: str
    negotiated_group: int       # NamedGroup codepoint from key_share
    client_share_len: int       # byte length of the client's key_share entry
    timestamp: float = field(default_factory=time.time)


class PQDowngradeSentinel:
    """Stateful inspector that quarantines downgraded / stripped sessions."""

    def __init__(self, strict_pqc: bool = True) -> None:
        self.strict_pqc = strict_pqc
        self.quarantine: Set[str] = set()

    def inspect(self, t: SessionTelemetry) -> Dict[str, Any]:
        """Return a verdict dict for one handshake."""
        group_name = GROUP_NAMES.get(t.negotiated_group, f"0x{t.negotiated_group:04X}")
        verdict: Dict[str, Any] = {
            "session_id": t.session_id,
            "client_ip": t.client_ip,
            "group": group_name,
            "status": "APPROVED",
            "action": "FORWARD",
            "reason": "Hybrid post-quantum key exchange present",
        }

        # 0. Already quarantined source -> block outright.
        if t.client_ip in self.quarantine:
            verdict.update(status="DROPPED", action="BLOCK",
                           reason="Source previously quarantined")
            return verdict

        # 1. Classical-only group while PQ is required -> downgrade attack.
        if t.negotiated_group in (CLASSICAL_X25519, CLASSICAL_SECP256R1):
            if self.strict_pqc:
                self.quarantine.add(t.client_ip)
                verdict.update(
                    status="CRITICAL", action="TERMINATE_AND_QUARANTINE",
                    reason=(f"Classical-only group {group_name} negotiated; "
                            f"post-quantum protection stripped (downgrade)"))
            else:
                verdict.update(status="WARN", action="FORWARD",
                               reason=f"Classical group {group_name} (PQ not enforced)")
            return verdict

        # 2. Hybrid claimed but share too short -> ML-KEM component stripped.
        if t.negotiated_group == HYBRID_X25519_MLKEM768:
            if t.client_share_len < EXPECTED_HYBRID_SHARE_LEN:
                self.quarantine.add(t.client_ip)
                verdict.update(
                    status="CRITICAL", action="RESET_AND_QUARANTINE",
                    reason=(f"Hybrid group claimed but key_share is "
                            f"{t.client_share_len} B (< {EXPECTED_HYBRID_SHARE_LEN} B); "
                            f"ML-KEM-768 share stripped"))
            return verdict

        # 3. Unknown / unexpected group -> flag for review.
        verdict.update(status="REVIEW", action="FLAG",
                       reason=f"Unrecognised group {group_name}")
        return verdict


def _print(label: str, v: Dict[str, Any]) -> None:
    print(f"  [{v['status']:<8}] {label}")
    print(f"      group={v['group']}  action={v['action']}")
    print(f"      reason: {v['reason']}")


def main() -> None:
    print("=" * 68)
    print(" pq_downgrade_guard.py: post-quantum TLS downgrade detector")
    print("=" * 68)
    guard = PQDowngradeSentinel(strict_pqc=True)

    print("\n[NORMAL] Hybrid handshake: X25519MLKEM768, 1216-byte share")
    benign = SessionTelemetry("sess-001", "10.0.1.10",
                              HYBRID_X25519_MLKEM768, EXPECTED_HYBRID_SHARE_LEN)
    _print("C2 link from 10.0.1.10", guard.inspect(benign))

    print("\n[ATTACK] Downgrade to X25519 only")
    attack = SessionTelemetry("sess-002", "10.0.1.45",
                              CLASSICAL_X25519, X25519_SHARE_LEN)
    _print("C2 link from 10.0.1.45", guard.inspect(attack))

    print("\n[ATTACK] Hybrid group with ML-KEM key removed (32-byte share)")
    stripped = SessionTelemetry("sess-003", "10.0.1.77",
                                HYBRID_X25519_MLKEM768, X25519_SHARE_LEN)
    _print("C2 link from 10.0.1.77", guard.inspect(stripped))

    print("\n[ATTACK] Quarantined address 10.0.1.45 reconnects")
    _print("C2 link from 10.0.1.45",
           guard.inspect(SessionTelemetry("sess-004", "10.0.1.45",
                                          HYBRID_X25519_MLKEM768,
                                          EXPECTED_HYBRID_SHARE_LEN)))
    print("\nQuarantine registry:", sorted(guard.quarantine))
    print("=" * 68)


if __name__ == "__main__":
    main()
