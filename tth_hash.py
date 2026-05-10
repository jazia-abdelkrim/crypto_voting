from __future__ import annotations

import hashlib
import json
import secrets
import string
from dataclasses import asdict, dataclass
from pathlib import Path


ALPHABET = string.ascii_uppercase + string.digits
CODE_LENGTH = 12


@dataclass(frozen=True)
class VoterCodes:
    voter_id: str
    n1: str
    n2: str
    tth_n2: str
    sha256_n2: str


def generate_code(length: int = CODE_LENGTH) -> str:
    return "".join(secrets.choice(ALPHABET) for _ in range(length))


def validate_code(code: str, length: int = CODE_LENGTH) -> bool:
    return len(code) == length and all(char in ALPHABET for char in code)


def normalize_code(code: str) -> str:
    return code.replace(" ", "").replace("-", "").upper()


def char_to_number(char: str) -> int:
    if char.isdigit():
        return int(char)
    if "A" <= char <= "Z":
        return ord(char) - ord("A") + 1
    raise ValueError(f"Unsupported character: {char!r}")


def code_to_numbers(code: str) -> list[int]:
    normalized = normalize_code(code)
    if not validate_code(normalized):
        raise ValueError("Code must contain exactly 12 uppercase letters/digits.")
    return [char_to_number(char) for char in normalized]


def tth_hash(code: str) -> str:
    """
    Compute a Toy Tetragraph Hash-like educational fingerprint.

    The PDF defines TTH as a pedagogical hash: convert letters to numbers,
    keep digits, split/pad to a block of 16 values, then apply transformations
    to produce a short fingerprint. The exact classroom formula is not printed
    in the provided PDF, so this implementation uses a clear deterministic
    16-value mixing process suitable for the project demo.
    """
    values = code_to_numbers(code)

    while len(values) < 16:
        values.append((values[-1] + len(values) + 7) % 27)

    state = [3, 5, 7, 11]
    for index, value in enumerate(values[:16]):
        slot = index % 4
        neighbor = state[(slot - 1) % 4]
        state[slot] = (state[slot] + value + neighbor * (index + 1)) % 97

    return "TTH-" + "-".join(f"{part:02X}" for part in state)


def sha256_fingerprint(code: str) -> str:
    normalized = normalize_code(code)
    if not validate_code(normalized):
        raise ValueError("Code must contain exactly 12 uppercase letters/digits.")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def create_voter_codes(voter_id: str) -> VoterCodes:
    n1 = generate_code()
    n2 = generate_code()
    return VoterCodes(
        voter_id=voter_id,
        n1=n1,
        n2=n2,
        tth_n2=tth_hash(n2),
        sha256_n2=sha256_fingerprint(n2),
    )


def public_commissioner_record(codes: VoterCodes) -> dict[str, str]:
    return {"voter_id": codes.voter_id, "n1": codes.n1, "tth_n2": codes.tth_n2}


def export_records(records: list[VoterCodes], output_path: str | Path) -> None:
    path = Path(output_path)
    data = {
        "private_demo": [asdict(record) for record in records],
        "public_for_commissioner": [
            public_commissioner_record(record) for record in records
        ],
    }
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def demo() -> None:
    records = [create_voter_codes(f"student_{number}") for number in range(1, 6)]
    export_records(records, "hash_demo.json")

    print("Hachage et Codes")
    print("=" * 32)
    for record in records:
        print(f"{record.voter_id}:")
        print(f"  N1              = {record.n1}")
        print(f"  N2 private      = {record.n2}")
        print(f"  TTH(N2) public  = {record.tth_n2}")
        print(f"  SHA256(N2) demo = {record.sha256_n2[:24]}...")
    print("\nExported: hash_demo.json")


if __name__ == "__main__":
    demo()
