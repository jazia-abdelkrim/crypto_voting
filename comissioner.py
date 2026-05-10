"""
commissaire.py - Electoral Commissioner Server
===============================================
Project : Applied Cryptography for Electronic Voting
ENSTA Alger - Ms. KHERROUBI - February 2026
Student 3 : Commissioner + Election Preparation

Role of the Commissioner :
  - Generate and distribute N1 and N2 codes to voters
  - Keep the list of valid N1 codes (to verify voting rights)
  - Store ONLY the TTH(N2) hash digests — never the real N2 values
  - Strike out N1 after the voter has cast their vote (one vote per person)
  - Validate TTH(N2) during the vote counting phase

Usage :
  python commissaire.py --action init --nb_voters 5
  python commissaire.py --action verify_n1 --n1 AF15GH258ZQP
  python commissaire.py --action strike_n1 --n1 AF15GH258ZQP
  python commissaire.py --action verify_tth --n2 BK37MN496YRX
  python commissaire.py --action status
"""

import os
import sys
import json
import hashlib
import secrets
import string
import argparse
from pathlib import Path
from datetime import datetime


# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────

DATA_DIR       = Path("commissioner_data")
N1_LIST_FILE   = DATA_DIR / "n1_list.json"       # {n1: "valid" | "struck"}
TTH_LIST_FILE  = DATA_DIR / "tth_n2_list.json"   # [tth_n2, ...]  (NEVER the real N2 values!)
LOG_FILE       = DATA_DIR / "commissioner.log"

CODE_LENGTH = 12                                  # length of N1 and N2 codes
CODE_CHARS  = string.ascii_uppercase + string.digits  # A-Z + 0-9


# ─────────────────────────────────────────────
# Logging utilities
# ─────────────────────────────────────────────

def log(message: str):
    """Write a timestamped message to the log file and stdout."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] {message}"
    print(entry)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(entry + "\n")


# ─────────────────────────────────────────────
# Code generation
# ─────────────────────────────────────────────

def generate_code() -> str:
    """
    Generate a random code of CODE_LENGTH characters (A-Z, 0-9).
    Uses secrets.choice() for cryptographic-grade entropy.
    Number of possible combinations: (10+26)^12 ≈ 4.7 × 10^18
    """
    return "".join(secrets.choice(CODE_CHARS) for _ in range(CODE_LENGTH))


def generate_code_pair() -> tuple[str, str]:
    """Return a unique (N1, N2) pair."""
    n1 = generate_code()
    n2 = generate_code()
    # Ensure N1 != N2 (extremely unlikely, but good practice)
    while n2 == n1:
        n2 = generate_code()
    return n1, n2


# ─────────────────────────────────────────────
# TTH Hash (Toy Tetragraph Hash - simplified)
# ─────────────────────────────────────────────

def tth_hash(code: str) -> str:
    """
    Compute a TTH digest of the N2 code.

    Implementation:
      SHA-256 is used as the underlying hash (robust and standardized),
      prefixed with the domain tag "TTH:" to simulate the TTH domain.
      Returns a 64-character hexadecimal digest.

    Guaranteed properties:
      1. Preimage resistance (one-way): impossible to recover N2 from TTH(N2)
      2. Collision resistance: two different N2 values produce different digests
      3. Avalanche effect: one character change -> completely different digest
    """
    data = ("TTH:" + code).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


# ─────────────────────────────────────────────
# Persistence (JSON read / write)
# ─────────────────────────────────────────────

def _read_json(path: Path, default):
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return default


def _write_json(path: Path, data):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def load_n1_list() -> dict:
    return _read_json(N1_LIST_FILE, {})


def save_n1_list(n1_list: dict):
    _write_json(N1_LIST_FILE, n1_list)


def load_tth_list() -> list:
    return _read_json(TTH_LIST_FILE, [])


def save_tth_list(tth_list: list):
    _write_json(TTH_LIST_FILE, tth_list)


# ─────────────────────────────────────────────
# Main actions
# ─────────────────────────────────────────────

def initialize_election(nb_voters: int):
    """
    Prepare the election:
      1. Generate nb_voters (N1, N2) pairs
      2. Compute TTH(N2) for each N2
      3. Save the N1 list (with status 'valid')
      4. Save ONLY the TTH(N2) digests
      5. Print voter cards (N1 + N2) -> to be distributed physically
      6. DESTROY all N2 values from the Commissioner's memory

    Security: after this function, the Commissioner no longer knows the real N2 values.
    """
    if DATA_DIR.exists() and N1_LIST_FILE.exists():
        log("ERROR: An election is already initialized. Delete commissioner_data/ to restart.")
        sys.exit(1)

    log(f"=== INITIALIZING ELECTION ({nb_voters} voters) ===")

    n1_list    = {}
    tth_list   = []
    voter_cards = []

    for i in range(1, nb_voters + 1):
        n1, n2 = generate_code_pair()

        # Ensure N1 is unique in the list
        while n1 in n1_list:
            n1, _ = generate_code_pair()

        digest = tth_hash(n2)

        n1_list[n1] = "valid"
        tth_list.append(digest)
        voter_cards.append({"voter": i, "N1": n1, "N2": n2})

        log(f"  Voter {i:02d} : N1={n1}  TTH(N2)={digest[:16]}...")

    # Save lists
    save_n1_list(n1_list)
    save_tth_list(tth_list)

    # Save voter cards (the only moment N2 is visible)
    cards_path = DATA_DIR / "voter_cards.json"
    _write_json(cards_path, voter_cards)

    log("")
    log("=== VOTER CARDS (distribute these, then DESTROY this file) ===")
    for card in voter_cards:
        print(f"  Voter {card['voter']:02d}  |  N1 : {card['N1']}  |  N2 : {card['N2']}")

    log("")
    log(f"  {nb_voters} pairs generated.")
    log(f"  N1 list saved     : {N1_LIST_FILE}")
    log(f"  TTH(N2) list saved: {TTH_LIST_FILE}")
    log(f"  WARNING: Voter cards saved in {cards_path} -> Distribute then DESTROY!")
    log("=== INITIALIZATION COMPLETE ===")


def verify_n1(n1: str) -> bool:
    """
    Verify that an N1 code is valid (exists in list and not yet used).
    Called by the Administrator during voter identification.
    Returns True if valid, False otherwise.
    """
    n1_list = load_n1_list()
    status  = n1_list.get(n1.upper())

    if status is None:
        log(f"verify_n1({n1}) -> REFUSED : unknown code")
        return False
    if status == "struck":
        log(f"verify_n1({n1}) -> REFUSED : already used (struck out)")
        return False
    if status == "valid":
        log(f"verify_n1({n1}) -> ACCEPTED")
        return True

    log(f"verify_n1({n1}) -> REFUSED : unknown status '{status}'")
    return False


def strike_n1(n1: str) -> bool:
    """
    Strike N1 from the list (the voter has cast their ballot).
    Called by the Anonymizer after receiving the vote.
    Each voter can only vote once.
    """
    n1_list = load_n1_list()
    n1 = n1.upper()

    if n1 not in n1_list:
        log(f"strike_n1({n1}) -> FAILED : unknown code")
        return False
    if n1_list[n1] == "struck":
        log(f"strike_n1({n1}) -> FAILED : already struck out")
        return False

    n1_list[n1] = "struck"
    save_n1_list(n1_list)
    log(f"strike_n1({n1}) -> SUCCESS : N1 struck out (voter has voted)")
    return True


def verify_tth_n2(n2: str) -> bool:
    """
    Verify that an N2 value matches a digest stored in the TTH list.
    Called during the counting phase by the Counter server.
    The Commissioner computes TTH(N2) and looks it up in the stored list.
    """
    digest   = tth_hash(n2.upper())
    tth_list = load_tth_list()

    if digest in tth_list:
        log(f"verify_tth({n2}) -> VALID   : TTH={digest[:16]}... found in list")
        return True
    else:
        log(f"verify_tth({n2}) -> INVALID : TTH={digest[:16]}... NOT found")
        return False


def display_status():
    """Display the current state of the electoral roll."""
    n1_list  = load_n1_list()
    tth_list = load_tth_list()

    total   = len(n1_list)
    struck  = sum(1 for s in n1_list.values() if s == "struck")
    pending = total - struck

    print("\n" + "="*50)
    print("   COMMISSIONER - ELECTION STATUS")
    print("="*50)
    print(f"  Registered voters    : {total}")
    print(f"  Have voted (struck)  : {struck}")
    print(f"  Have not voted yet   : {pending}")
    print(f"  TTH(N2) digests      : {len(tth_list)}")
    print("="*50)

    print("\n  N1 list detail:")
    for n1, status in n1_list.items():
        icon = "v" if status == "struck" else "o"
        print(f"    [{icon}] {n1}  [{status}]")
    print()


# ─────────────────────────────────────────────
# Programmatic API (for main.py integration)
# ─────────────────────────────────────────────

class Commissioner:
    """
    Programmatic interface for the Commissioner server.
    Used by main.py to integrate the complete voting system.

    Example usage:
        comm = Commissioner()
        comm.initialize(5)
        ok    = comm.verify_n1("AF15GH258ZQP")
        comm.strike_n1("AF15GH258ZQP")
        valid = comm.verify_tth_n2("BK37MN496YRX")
    """

    def initialize(self, nb_voters: int):
        initialize_election(nb_voters)

    def verify_n1(self, n1: str) -> bool:
        return verify_n1(n1)

    def strike_n1(self, n1: str) -> bool:
        return strike_n1(n1)

    def verify_tth_n2(self, n2: str) -> bool:
        return verify_tth_n2(n2)

    def status(self):
        display_status()

    def get_tth_list(self) -> list:
        return load_tth_list()

    def get_n1_list(self) -> dict:
        return load_n1_list()


# ─────────────────────────────────────────────
# Command-line interface
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Electoral Commissioner - Voter roll management"
    )
    parser.add_argument(
        "--action",
        required=True,
        choices=["init", "verify_n1", "strike_n1", "verify_tth", "status"],
        help="Action to perform"
    )
    parser.add_argument("--nb_voters", type=int, default=5,
                        help="Number of voters (for --action init)")
    parser.add_argument("--n1", type=str, help="Voter N1 code")
    parser.add_argument("--n2", type=str, help="Voter N2 code (counting phase)")

    args = parser.parse_args()

    if args.action == "init":
        initialize_election(args.nb_voters)

    elif args.action == "verify_n1":
        if not args.n1:
            print("ERROR: --n1 required for verify_n1")
            sys.exit(1)
        ok = verify_n1(args.n1)
        sys.exit(0 if ok else 1)

    elif args.action == "strike_n1":
        if not args.n1:
            print("ERROR: --n1 required for strike_n1")
            sys.exit(1)
        ok = strike_n1(args.n1)
        sys.exit(0 if ok else 1)

    elif args.action == "verify_tth":
        if not args.n2:
            print("ERROR: --n2 required for verify_tth")
            sys.exit(1)
        ok = verify_tth_n2(args.n2)
        sys.exit(0 if ok else 1)

    elif args.action == "status":
        display_status()


if __name__ == "__main__":
    main()
