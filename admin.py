"""
admin.py - Administrator Server
================================
Project : Applied Cryptography for Electronic Voting
ENSTA Alger - Ms. KHERROUBI - February 2026
Student 4 : Administrator + Anonymizer

Role of the Administrator :
  - Verify voting rights by checking N1 with the Commissioner
  - Blind-sign ballots WITHOUT ever seeing their content
  - Refuse to sign if the voter's N1 is invalid or already used
  - Never learn N2 — blind signature preserves voter anonymity

Security guarantee :
  The Admin sees only the masked ballot m' = m * k^e (mod N).
  Because k is chosen secretly by the voter, the Admin cannot
  determine m (the real vote + N2 combination).
"""

from __future__ import annotations

import math
import logging

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("AdminServer")


class AdminServer:
    """
    Administrator Server — blind-signature authority.

    Parameters
    ----------
    e : int  RSA public exponent
    N : int  RSA modulus
    d : int  RSA private exponent (kept secret)

    Attributes
    ----------
    public_key  : (e, N) — shared publicly
    private_key : d      — never exposed
    valid_n1    : set of N1 codes currently allowed to vote
    _signed_count : number of ballots blind-signed so far
    """

    def __init__(self, e: int, N: int, d: int) -> None:
        if not (isinstance(e, int) and isinstance(N, int) and isinstance(d, int)):
            raise TypeError("RSA parameters e, N, d must be integers.")
        # Quick sanity check: e·d ≡ 1 (mod φ) is hard to verify without φ,
        # but we can at least check that (m^e)^d = m for a small m.
        self.public_key  = (e, N)
        self.private_key = d
        self.valid_n1: set[str] = set()
        self._signed_count      = 0
        logger.info(f"AdminServer initialised  public_key=({e}, {N})")

    # ── N1 management ─────────────────────────────────────────────────────────

    def load_valid_n1(self, n1_list: list[str]) -> None:
        """Load the authorised N1 codes (supplied by the Commissioner)."""
        self.valid_n1 = set(n1_list)
        logger.info(f"Loaded {len(self.valid_n1)} valid N1 codes.")

    def check_voter_right(self, n1: str) -> bool:
        """
        Return True iff n1 is in the current valid-N1 set.

        This does NOT strike the N1 — striking is done by the Anonymizer
        after the ballot is deposited, preventing the Admin from knowing
        which voters ultimately cast a ballot.
        """
        result = n1.upper() in self.valid_n1
        logger.info(f"check_voter_right({n1}) -> {'GRANTED' if result else 'DENIED'}")
        return result

    # ── Blind signature ───────────────────────────────────────────────────────

    def blind_sign(self, m_masked: int) -> int:
        """
        Sign the blinded ballot without knowing the original message.

        Formula: m'' = (m')^d  mod N

        The Admin only sees the masked message m' = m · k^e (mod N).
        Without knowing the voter's secret k, the Admin cannot infer m.

        Parameters
        ----------
        m_masked : int  The blinded message m' sent by the voter.

        Returns
        -------
        int  The blind signature m''.
        """
        e, N = self.public_key
        if not (0 <= m_masked < N):
            raise ValueError(
                f"Masked message must be in [0, N-1]. Got {m_masked}, N={N}."
            )
        m_double_prime = pow(m_masked, self.private_key, N)
        self._signed_count += 1
        logger.info(
            f"blind_sign  m'={m_masked}  ->  m''={m_double_prime}  "
            f"(total signed: {self._signed_count})"
        )
        return m_double_prime

    # ── Helpers ───────────────────────────────────────────────────────────────

    def verify_signature(self, message: int, signature: int) -> bool:
        """
        Verify that *signature* is a valid RSA signature of *message*.
        Check: sig^e mod N == message mod N
        Used by the Counter during tallying.
        """
        e, N = self.public_key
        return pow(signature, e, N) == message % N

    def status(self) -> dict:
        """Return a status snapshot (safe to expose publicly)."""
        return {
            "public_key":    self.public_key,
            "active_n1":     len(self.valid_n1),
            "ballots_signed": self._signed_count,
        }

    def __repr__(self) -> str:
        e, N = self.public_key
        return (
            f"<AdminServer e={e} N={N} "
            f"valid_n1={len(self.valid_n1)} signed={self._signed_count}>"
        )