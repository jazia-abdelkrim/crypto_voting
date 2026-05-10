"""
anonymiseur.py - Anonymizer Server (Ballot Box)
================================================
Project : Applied Cryptography for Electronic Voting
ENSTA Alger - Ms. KHERROUBI - February 2026
Student 4 : Administrator + Anonymizer

Role of the Anonymizer :
  - Act as the physical ballot box: accept (N1, encrypted_vote, signature)
  - Verify N1 with the Commissioner before accepting the vote
  - Strike N1 from the Commissioner's list (one vote per person)
  - Store ONLY (encrypted_vote, signature) — identity is immediately discarded
  - Forward the anonymous ballot list to the Counter for tallying

Security guarantees :
  • The Anonymizer never knows N2  → cannot reconstruct the vote.
  • The vote is encrypted with the Counter's public key  → cannot read it.
  • Random padding bits in the ballot prevent linking the encrypted ballot
    to the decrypted result (in a production system).
  • Once N1 is struck, the voter cannot vote twice.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("AnonymizerServer")


@dataclass
class AnonymousBallot:
    """
    The only record the Anonymizer keeps.
    No voter identity is stored — anonymity is guaranteed by design.
    """
    encrypted_vote: int
    signature:      int
    received_at:    str = field(default_factory=lambda: datetime.now().isoformat())


class AnonymizerServer:
    """
    Anonymizer Server — the digital ballot box.

    Attributes
    ----------
    ballot_box : list of AnonymousBallot
        Ordered list of accepted, anonymous ballots.
    used_n1    : set of str
        N1 codes that have already been used this session.
        Provides a local cache; the authoritative struck list lives at the Commissioner.
    _rejected  : int
        Count of rejected vote attempts (for statistics).
    """

    def __init__(self) -> None:
        self.ballot_box: list[AnonymousBallot] = []
        self.used_n1:    set[str]              = set()
        self._rejected:  int                   = 0
        logger.info("AnonymizerServer initialised — ballot box is empty.")

    # ── Core method ───────────────────────────────────────────────────────────

    def receive_vote(
        self,
        n1:                    str,
        encrypted_vote:        int,
        signature:             int,
        commissioner_valid_n1: set[str],
    ) -> tuple[bool, str]:
        """
        Accept or reject a vote submission.

        Protocol:
          1. Check n1 is in the Commissioner's valid-N1 set (voter is registered).
          2. Check n1 has not been used before (no double voting).
          3. Strike n1 from the Commissioner's set (in-place mutation of the set).
          4. Cache n1 locally in used_n1.
          5. Store (encrypted_vote, signature) anonymously — identity is dropped.

        Parameters
        ----------
        n1                    : voter's identification code
        encrypted_vote        : vote encrypted with Counter's public key
        signature             : Admin's blind signature on the ballot
        commissioner_valid_n1 : mutable set owned by the Commissioner; will be mutated

        Returns
        -------
        (True,  success_message) on acceptance
        (False, rejection_reason) on rejection
        """
        n1 = n1.upper()

        # Guard 1 — voter must be registered and not yet struck
        if n1 not in commissioner_valid_n1:
            self._rejected += 1
            reason = "N1 not found in Commissioner's valid list (unregistered or already struck)."
            logger.warning(f"receive_vote REJECTED  n1={n1}  reason={reason}")
            return False, f"❌ {reason}"

        # Guard 2 — local double-vote cache (fast path)
        if n1 in self.used_n1:
            self._rejected += 1
            reason = "N1 already used in this session (double-vote attempt)."
            logger.warning(f"receive_vote REJECTED  n1={n1}  reason={reason}")
            return False, f"❌ {reason}"

        # Strike N1 — the voter has cast their ballot; cannot vote again
        commissioner_valid_n1.discard(n1)
        self.used_n1.add(n1)

        # Store the anonymous ballot (identity intentionally discarded)
        ballot = AnonymousBallot(encrypted_vote=encrypted_vote, signature=signature)
        self.ballot_box.append(ballot)

        logger.info(
            f"receive_vote ACCEPTED  n1={n1}  "
            f"enc={encrypted_vote}  sig={signature}  "
            f"ballot_no={len(self.ballot_box)}"
        )
        return True, f"✅ Vote accepted and stored anonymously (ballot #{len(self.ballot_box)})."

    # ── Read-only accessors ───────────────────────────────────────────────────

    def get_ballots_for_counter(self) -> list[dict]:
        """
        Return the list of anonymous ballots for the Counter.
        Each entry contains only (encrypted_vote, signature) — no voter identity.
        """
        return [
            {"encrypted_vote": b.encrypted_vote, "signature": b.signature}
            for b in self.ballot_box
        ]

    def status(self) -> dict:
        """Return a safe status snapshot."""
        return {
            "ballots_accepted": len(self.ballot_box),
            "ballots_rejected": self._rejected,
            "unique_voters":    len(self.used_n1),
        }

    def __repr__(self) -> str:
        return (
            f"<AnonymizerServer ballots={len(self.ballot_box)} "
            f"rejected={self._rejected}>"
        )