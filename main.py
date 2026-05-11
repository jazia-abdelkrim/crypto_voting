from __future__ import annotations

import math
import argparse
import shutil
from pathlib import Path

# ── local modules ──────────────────────────────────────────────────────────────
from commissaire   import Commissioner
from admin         import AdminServer
from anonymiseur   import AnonymizerServer
from decompte      import Counter
from tth_hash      import create_voter_codes, tth_hash, normalize_code



# Fixed RSA parameters (match the exercises)


ADMIN_E, ADMIN_N, ADMIN_D = 27, 55, 3    # Exercise 2 keys
COUNTER_E, COUNTER_N      = 3,  583      # Exercise 4 keys


# Helpers


def _blind_signature_protocol(
    message: int,
    admin: AdminServer,
    blinding_k: int = 2,
) -> tuple[int, int]:
    """
    Full 4-step blind signature (voter side).

    Returns (message, signature) — the signed ballot pair.
    """
    e, N = admin.public_key

    # Step 1 – Alice picks blinding factor k (coprime with N)
    k = blinding_k
    while math.gcd(k, N) != 1:
        k += 1

    # Step 2 – Alice blinds the message
    m_prime = (message * pow(k, e, N)) % N

    # Step 3 – Admin signs the blinded message (without seeing m)
    m_double_prime = admin.blind_sign(m_prime)

    # Step 4 – Alice removes the blinding factor
    k_inv     = pow(k, -1, N)
    signature = (m_double_prime * k_inv) % N

    return message, signature


def _build_ballot_message(vote_value: int, n2_str: str, admin_N: int) -> int:
    """Reconstruct the integer message m from vote + N2 (classroom simplification)."""
    try:
        n2_num = int(str(n2_str)[:2])
    except (ValueError, TypeError):
        n2_num = 0
    return (vote_value * 1000 + n2_num) % admin_N



# Main voting flow


def run_election(nb_voters: int = 5, vote_values: list[int] | None = None) -> None:
    """
    Simulate a complete election with nb_voters voters.

    Parameters
    ----------
    nb_voters   : number of voters to simulate
    vote_values : list of votes (integers); defaults to [7]*nb_voters
    """

    if vote_values is None:
        vote_values = [7] * nb_voters
    if len(vote_values) < nb_voters:
        # Pad with last value
        vote_values += [vote_values[-1]] * (nb_voters - len(vote_values))

    _banner("ELECTRONIC VOTING SYSTEM — FULL INTEGRATION")

    # ── Clean previous run data ────────────────────────────────────────────────
    for folder in ("commissioner_data", "counter_data"):
        if Path(folder).exists():
            shutil.rmtree(folder)

  
    # PHASE 0 — Server initialisation
   
    _section("PHASE 0 · Server Initialisation")

    commissioner = Commissioner()
    admin        = AdminServer(ADMIN_E, ADMIN_N, ADMIN_D)
    anonymizer   = AnonymizerServer()
    counter      = Counter()

    print(f"  Admin   public key  : (e={ADMIN_E},   N={ADMIN_N})")
    print(f"  Admin   private key : d={ADMIN_D}")
    print(f"  Counter public key  : (e={COUNTER_E}, N={COUNTER_N})")
    print()

    
    # PHASE 1 — Election preparation (Commissioner)
    
    _section("PHASE 1 · Election Preparation")

    # Generate voter codes with tth_hash module
    voter_records = [create_voter_codes(f"voter_{i:02d}") for i in range(1, nb_voters + 1)]

    n1_list  = {rec.n1: "valid" for rec in voter_records}
    tth_list = [rec.tth_n2 for rec in voter_records]

    # Bootstrap commissioner with generated data
    commissioner._n1_list  = n1_list
    commissioner._tth_list = tth_list

    # Load N1s into Admin
    admin.load_valid_n1(list(n1_list.keys()))

    print(f"  {nb_voters} voter codes generated.")
    print()
    for rec in voter_records:
        print(f"    {rec.voter_id}  N1={rec.n1}  N2={rec.n2}  TTH={rec.tth_n2[:20]}...")
    print()

   
    # PHASE 2 — Voting
    
    _section("PHASE 2 · Voters Cast Their Ballots")

    for idx, rec in enumerate(voter_records):
        vote = vote_values[idx]
        _subsection(f"{rec.voter_id}  (vote = {vote})")

        # 2a – Voter identifies with N1
        if not admin.check_voter_right(rec.n1):
            print(f"    [DENIED] {rec.voter_id} has no voting right — skipping.")
            continue
        print(f"    N1 check: APPROVED")

        # 2b – Build ballot message
        m = _build_ballot_message(vote, rec.n2, ADMIN_N)
        try:
            n2_num = int(str(rec.n2)[:2])
        except (ValueError, TypeError):
            n2_num = 0
        print(f"    Ballot message m = ({vote} * 1000 + {n2_num}) mod {ADMIN_N} = {m}")

        # 2c – Blind signature with Admin
        msg, sig = _blind_signature_protocol(m, admin)
        sig_ok   = pow(sig, ADMIN_E, ADMIN_N) == m % ADMIN_N
        print(f"    Blind signature s = {sig}   verify: s^e mod N = {pow(sig, ADMIN_E, ADMIN_N)}  {'✓' if sig_ok else '✗'}")

        # 2d – Encrypt vote for Counter
        enc_vote = pow(vote, COUNTER_E, COUNTER_N)
        print(f"    Encrypted vote   = {vote}^{COUNTER_E} mod {COUNTER_N} = {enc_vote}")

        # 2e – Drop in ballot box via Anonymizer (uses working_n1 set)
        working_n1 = set(admin.valid_n1)
        success, msg_text = anonymizer.receive_vote(rec.n1, enc_vote, sig, working_n1)
        admin.valid_n1 = working_n1   # sync back the struck N1
        print(f"    Anonymizer: {msg_text}")

        # 2f – Counter stores the ballot (with N2 for later TTH check)
        counter.receive_ballot(enc_vote, sig, n2=rec.n2)

   
    # PHASE 3 — Tallying
    
    _section("PHASE 3 · Tallying (Counter + Commissioner)")

    # Build the TTH list the Commissioner holds
    commissioner_tth = tth_list
    results = counter.tally(commissioner_tth_list=commissioner_tth)

    # ══════════════════════════════════════════════
    # PHASE 4 — Results
    # ══════════════════════════════════════════════
    _section("PHASE 4 · Final Results")
    counter.display()

    # ── Double-vote attempt ────────────────────────────────────────────────────
    _section("BONUS · Double-Vote Attack Test")
    rec    = voter_records[0]
    vote   = vote_values[0]
    m      = _build_ballot_message(vote, rec.n2, ADMIN_N)
    _, sig = _blind_signature_protocol(m, admin)
    enc    = pow(vote, COUNTER_E, COUNTER_N)

    working_n1 = set(admin.valid_n1)
    success, msg_text = anonymizer.receive_vote(rec.n1, enc, sig, working_n1)
    print(f"  Re-vote attempt by {rec.voter_id}: {msg_text}")
    print(f"  Result: {'BLOCKED ✓' if not success else 'LEAKED — bug!'}")



# Formatting helpers


def _banner(text: str) -> None:
    line = "═" * 60
    print(f"\n{line}")
    print(f"  {text}")
    print(f"{line}\n")


def _section(title: str) -> None:
    print(f"\n{'─'*60}")
    print(f"  ▶  {title}")
    print(f"{'─'*60}")


def _subsection(title: str) -> None:
    print(f"\n  ── {title} ──")



# Commissioner thin wrapper
# (commissaire.py uses file I/O; we patch it for in-memory demo)


class Commissioner:          # noqa: F811  (shadow the import for in-memory use)
    """Thin in-memory Commissioner for main.py integration."""

    def __init__(self):
        self._n1_list:  dict[str, str] = {}
        self._tth_list: list[str]      = []

    def verify_n1(self, n1: str) -> bool:
        return self._n1_list.get(n1) == "valid"

    def strike_n1(self, n1: str) -> bool:
        if self._n1_list.get(n1) == "valid":
            self._n1_list[n1] = "struck"
            return True
        return False

    def verify_tth_n2(self, n2: str) -> bool:
        digest = tth_hash(normalize_code(n2))
        return digest in self._tth_list

    def get_tth_list(self) -> list[str]:
        return self._tth_list



# Entry point


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Electronic Voting System — Full Simulation"
    )
    parser.add_argument("--voters", type=int, default=5,
                        help="Number of voters (default: 5)")
    parser.add_argument("--votes",  type=str, default=None,
                        help="Comma-separated vote values e.g. '7,8,7,9,7'")
    args = parser.parse_args()

    vote_values = None
    if args.votes:
        try:
            vote_values = [int(v.strip()) for v in args.votes.split(",")]
        except ValueError:
            print("ERROR: --votes must be comma-separated integers.")
            return

    run_election(nb_voters=args.voters, vote_values=vote_values)


if __name__ == "__main__":
    main()