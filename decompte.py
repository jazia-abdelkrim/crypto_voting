from __future__ import annotations

import json
import math
import argparse
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict



# Configuration  (matches commissaire.py + rsa.py)


COUNTER_N   = 583          # RSA modulus  583 = 11 × 53
COUNTER_E   = 3            # public exponent
COUNTER_PHI = 520          # phi(583) = (11-1)*(53-1)
COUNTER_D   = 347          # private exponent  (3*347 = 1041 = 2*520 + 1)

# Admin public key (used to verify blind signatures)
ADMIN_E = 27
ADMIN_N = 55

DATA_DIR      = Path("counter_data")
BALLOTS_FILE  = DATA_DIR / "received_ballots.json"
RESULTS_FILE  = DATA_DIR / "tally_results.json"
LOG_FILE      = DATA_DIR / "counter.log"



# Logging


def log(message: str) -> None:
    ts    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{ts}] {message}"
    print(entry)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as fh:
        fh.write(entry + "\n")



# RSA helpers (self-contained, no import of rsa.py)


def _rsa(base: int, exp: int, mod: int) -> int:
    """Python's built-in modular exponentiation (fast, constant-time)."""
    return pow(base, exp, mod)


def decrypt_vote(encrypted_vote: int) -> int:
    """Decrypt a ballot encrypted with the Counter's public key."""
    return _rsa(encrypted_vote, COUNTER_D, COUNTER_N)


def verify_admin_signature(message: int, signature: int) -> bool:
    """
    Verify that *signature* was produced by the Admin's private key.
    Check: sig^e mod N_admin == message mod N_admin
    """
    recovered = _rsa(signature, ADMIN_E, ADMIN_N)
    return recovered == (message % ADMIN_N)



# Persistence


def _read_json(path: Path, default):
    if path.exists():
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    return default


def _write_json(path: Path, data) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)


def load_ballots() -> list[dict]:
    return _read_json(BALLOTS_FILE, [])


def save_ballots(ballots: list[dict]) -> None:
    _write_json(BALLOTS_FILE, ballots)


def load_results() -> dict:
    return _read_json(RESULTS_FILE, {})


def save_results(results: dict) -> None:
    _write_json(RESULTS_FILE, results)



# Core actions


def receive_ballot(encrypted_vote: int, signature: int, n2: str | None = None) -> dict:
    """
    Accept an encrypted ballot from the Anonymizer.

    Parameters
    ----------
    encrypted_vote : ciphertext produced with (e=COUNTER_E, N=COUNTER_N)
    signature      : Admin's blind signature on the ballot message
    n2             : voter's N2 code (sent separately at tallying time)

    Returns a ballot record stored for later tallying.
    """
    ballot = {
        "encrypted_vote": encrypted_vote,
        "signature":      signature,
        "n2":             n2,
        "status":         "pending",
    }
    ballots = load_ballots()
    ballots.append(ballot)
    save_ballots(ballots)
    log(f"receive_ballot  enc={encrypted_vote}  sig={signature}  n2={n2 or '(pending)'}")
    return ballot


def tally_votes(commissioner_tth_list: list[str] | None = None) -> dict:
    """
    Decrypt, verify, and count all ballots.

    Steps for each ballot:
      1. Decrypt the vote with the Counter's private key.
      2. Verify the Admin's blind signature.
      3. (Optional) Ask the Commissioner to validate N2 via TTH.
      4. Accumulate valid votes.

    Returns a results dict with counts and a public audit log.
    """
    ballots = load_ballots()
    if not ballots:
        log("tally_votes: no ballots found.")
        return {}

    counts:    dict[int, int] = {}
    audit_log: list[dict]     = []
    valid      = 0
    rejected   = 0

    log(f"=== TALLYING {len(ballots)} BALLOT(S) ===")

    for idx, ballot in enumerate(ballots, start=1):
        enc_vote  = ballot["encrypted_vote"]
        signature = ballot["signature"]
        n2        = ballot.get("n2")

        # Step 1 – decrypt
        vote = decrypt_vote(enc_vote)

        # Step 2 – reconstruct ballot message (same formula as the voter)
        # m = (vote * 1000 + n2_prefix) % ADMIN_N  — simplified classroom formula
        # n2_prefix is the first two characters parsed as int if digits, else 0.
        if n2 is not None:
            try:
                prefix = str(n2)[:2]
                n2_num = int(prefix) if prefix.isdigit() else 0
                m = (vote * 1000 + n2_num) % ADMIN_N
            except (ValueError, TypeError):
                m = vote % ADMIN_N
        else:
            m = vote % ADMIN_N

        sig_ok = verify_admin_signature(m, signature)

        # Step 3 – TTH check (optional, requires Commissioner cooperation)
        tth_ok = True
        if commissioner_tth_list is not None and n2 is not None:
            from tth_hash import tth_hash, normalize_code
            digest = tth_hash(normalize_code(str(n2)))
            tth_ok = digest in commissioner_tth_list
            log(f"  Ballot {idx}: TTH check {'PASSED' if tth_ok else 'FAILED'}")

        if sig_ok and tth_ok:
            counts[vote] = counts.get(vote, 0) + 1
            audit_log.append({
                "ballot":    idx,
                "vote":      vote,
                "n2":        n2,
                "sig_valid": True,
                "tth_valid": tth_ok,
                "status":    "counted",
            })
            valid += 1
            log(f"  Ballot {idx}: vote={vote}  sig=VALID  -> COUNTED")
        else:
            reason = []
            if not sig_ok:
                reason.append("bad signature")
            if not tth_ok:
                reason.append("TTH mismatch")
            audit_log.append({
                "ballot":    idx,
                "vote":      vote,
                "n2":        n2,
                "sig_valid": sig_ok,
                "tth_valid": tth_ok,
                "status":    "rejected",
                "reason":    ", ".join(reason),
            })
            rejected += 1
            log(f"  Ballot {idx}: vote={vote}  -> REJECTED ({', '.join(reason)})")

    results = {
        "total_ballots": len(ballots),
        "valid_votes":   valid,
        "rejected":      rejected,
        "tally":         counts,
        "audit_log":     audit_log,
        "tallied_at":    datetime.now().isoformat(),
    }
    save_results(results)
    log(f"=== TALLY COMPLETE  valid={valid}  rejected={rejected} ===")
    _print_results(results)
    return results


def display_results() -> None:
    """Pretty-print the saved tally results."""
    results = load_results()
    if not results:
        print("No results found. Run --action tally first.")
        return
    _print_results(results)


def _print_results(results: dict) -> None:
    tally    = results.get("tally", {})
    total    = results.get("total_ballots", 0)
    valid    = results.get("valid_votes", 0)
    rejected = results.get("rejected", 0)

    print()
    print("=" * 55)
    print("   COUNTER - ELECTION RESULTS")
    print("=" * 55)
    print(f"  Total ballots received : {total}")
    print(f"  Valid votes counted    : {valid}")
    print(f"  Rejected ballots       : {rejected}")
    print()
    if tally:
        print("  Vote breakdown:")
        for vote_val, count in sorted(tally.items()):
            bar = "█" * count
            print(f"    Vote {vote_val:>3} : {count:>3}  {bar}")
        winner = max(tally, key=tally.get)
        print(f"\n  Winner / Most popular : Vote = {winner}  ({tally[winner]} vote(s))")
    else:
        print("  No valid votes to display.")
    print("=" * 55)

    audit = results.get("audit_log", [])
    if audit:
        print("\n  Public Audit Log  (voters can verify their own N2):")
        for entry in audit:
            status = "✓" if entry["status"] == "counted" else "✗"
            n2_disp = entry.get("n2") or "(no N2)"
            print(f"    [{status}] Ballot {entry['ballot']:>2}  vote={entry['vote']}  N2={n2_disp}")
    print()



# Programmatic API  (used by main.py)


class Counter:
    """
    Programmatic interface for the Counter server.

    Example usage:
        counter = Counter()
        counter.receive_ballot(343, 54, n2="14")
        results = counter.tally(commissioner_tth_list=[...])
    """

    def receive_ballot(self, encrypted_vote: int,
                       signature: int,
                       n2: str | None = None) -> dict:
        return receive_ballot(encrypted_vote, signature, n2)

    def tally(self, commissioner_tth_list: list[str] | None = None) -> dict:
        return tally_votes(commissioner_tth_list)

    def results(self) -> dict:
        return load_results()

    def display(self) -> None:
        display_results()

    # Expose keys for transparency
    @property
    def public_key(self) -> tuple[int, int]:
        return (COUNTER_E, COUNTER_N)



# CLI


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Electoral Counter — ballot decryption and tallying"
    )
    parser.add_argument(
        "--action",
        required=True,
        choices=["receive", "tally", "results"],
        help="Action to perform",
    )
    parser.add_argument("--ballot", type=int, help="Encrypted vote (for receive)")
    parser.add_argument("--sig",    type=int, help="Admin blind signature (for receive)")
    parser.add_argument("--n2",     type=str, help="Voter N2 code (for receive)")
    args = parser.parse_args()

    if args.action == "receive":
        if args.ballot is None or args.sig is None:
            print("ERROR: --ballot and --sig are required for receive")
            return
        receive_ballot(args.ballot, args.sig, args.n2)

    elif args.action == "tally":
        tally_votes()

    elif args.action == "results":
        display_results()


if __name__ == "__main__":
    main()