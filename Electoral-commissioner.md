# Student 3 Report — Electoral Commissioner
**Project: Applied Cryptography for Electronic Voting**
ENSTA Alger · Ms. KHERROUBI · February 2026

---

## 1. Role of the Commissioner in the Protocol

The Commissioner is the **guardian of the electoral roll**. His role is to guarantee two fundamental properties:

1. **One voter = one vote**: prevent the same person from voting twice.
2. **Vote anonymity**: the Commissioner knows *who* has voted, but never knows *what* they voted for.

To achieve this, he maintains two separate lists:

| List | Content | Created | Destroyed |
|---|---|---|---|
| **N1 list** | `{N1 : "valid" \| "struck"}` | At initialization | Never (kept for audit) |
| **TTH(N2) list** | `[digest1, digest2, ...]` | At initialization | Never (used for counting) |

> **What the Commissioner NEVER sees**: the vote content, the real N2 values, or the signed ballot.

---

## 2. Generating N1 and N2 Codes

### Generation algorithm

```python
CODE_CHARS  = string.ascii_uppercase + string.digits  # 36 characters
CODE_LENGTH = 12

def generate_code() -> str:
    return "".join(secrets.choice(CODE_CHARS) for _ in range(CODE_LENGTH))
```

### Why `secrets.choice()` and not `random.choice()`?

Python's `random` module uses the **Mersenne Twister**, a pseudo-random generator whose internal state can be reconstructed after observing enough output values. The `secrets` module uses `/dev/urandom` (Linux) — a source of hardware entropy that is computationally unpredictable. For cryptographic codes, only `secrets` is acceptable.

### Size of the code space

$$|\text{CODE}| = 36^{12} \approx 4.74 \times 10^{18}$$

This represents approximately 61.5 bits of entropy. The probability of a collision or of guessing a code by brute force is negligible.

---

## 3. The TTH Hash Function

### Core property: preimage resistance (one-way)

**Formal definition**: a function `H` is preimage-resistant if, given `y = H(x)`, it is *computationally infeasible* to find `x`.

**Application in the protocol**: the Commissioner stores `TTH(N2)` but destroys `N2`. This means:

- If the Commissioner is compromised → the attacker gets `TTH(N2)`, but cannot recover `N2`.
- Without `N2`, it is impossible to forge a valid ballot (since the ballot contains `N2`).

### TTH implementation

```python
def tth_hash(code: str) -> str:
    data = ("TTH:" + code).encode("utf-8")
    return hashlib.sha256(data).hexdigest()
```

**SHA-256** is used with a domain prefix `"TTH:"` (domain separation). SHA-256 guarantees:

1. **Preimage resistance**: recovering `N2` from `TTH(N2)` would require ~2²⁵⁶ operations.
2. **Collision resistance**: two different N2 values produce different digests (~2¹²⁸ operations for a collision).
3. **Avalanche effect**: a single bit difference in `N2` produces a completely different digest.

### Numerical example

```
N2       = "BK37MN496YRX"
TTH(N2)  = sha256("TTH:BK37MN496YRX")
         = "a3f8c2d1..." (64 hexadecimal characters)
```

---

## 4. Step-by-Step Workflow

### 4.1 Initialization (before the vote)

```
For each voter i :
  1. Generate N1_i, N2_i   (cryptographic random)
  2. Compute digest_i = TTH(N2_i)
  3. Add N1_i to N1_list with status "valid"
  4. Add digest_i to TTH_list
  5. Print voter card (N1_i, N2_i) -> hand to voter

DESTROY all N2 values (Commissioner keeps only TTH(N2))
```

### 4.2 During the vote (identification phase)

The Administrator calls the Commissioner with the voter's N1:

```
commissioner.verify_n1(N1) :
  - N1 unknown?        -> REFUSED
  - N1 status "struck"? -> REFUSED (already voted)
  - N1 status "valid"?  -> ACCEPTED
```

### 4.3 After ballot deposit (striking phase)

The Anonymizer notifies the Commissioner that the voter has successfully voted:

```
commissioner.strike_n1(N1) :
  - N1 -> status "struck"
  - Logged with timestamp
```

### 4.4 Vote counting (TTH verification)

The Counter transmits the N2 value from the decrypted ballot:

```
commissioner.verify_tth_n2(N2) :
  - Compute TTH(N2)
  - Search in TTH_list
  - Found?     -> ballot is valid
  - Not found? -> ballot rejected (fraudulent)
```

---

## 5. Why the Commissioner Cannot Commit Fraud

The Commissioner knows:
- The **N1 list** (who has the right to vote) ✓
- The **TTH(N2) digests** ✓

The Commissioner does **NOT** know:
- The **real N2 values** → he cannot forge a valid ballot
- The **vote content** → he never sees any ballot
- The **Administrator's signature** → he cannot authenticate a fake ballot

**Conclusion**: even if malicious, the Commissioner is technically unable to create valid votes or to know what any voter chose.

---

## 6. Code Structure (`commissaire.py`)

```
commissaire.py
│
├── generate_code()          # Secure code generation (secrets module)
├── generate_code_pair()     # Unique (N1, N2) pair
├── tth_hash(code)           # SHA-256 digest with TTH domain prefix
│
├── initialize_election()    # Prepare voter roll + voter cards
├── verify_n1(n1)            # Validate voting right
├── strike_n1(n1)            # Mark voter as having voted
├── verify_tth_n2(n2)        # Validate an N2 during counting
├── display_status()         # Show current election state
│
├── class Commissioner       # Programmatic API for main.py
└── main()                   # CLI interface (argparse)
```

### Generated files

| File | Content | Access |
|---|---|---|
| `commissioner_data/n1_list.json` | `{N1: status}` | Commissioner only |
| `commissioner_data/tth_n2_list.json` | `[TTH(N2), ...]` | Commissioner only |
| `commissioner_data/voter_cards.json` | `(N1, N2)` pairs | **Destroy after distribution** |
| `commissioner_data/commissioner.log` | Timestamped audit log | Audit |

---

## 7. Validation Tests

```bash
# Initialize the election (5 voters)
python commissaire.py --action init --nb_voters 5

# Verify an N1 code before voting
python commissaire.py --action verify_n1 --n1 AF15GH258ZQP
# -> ACCEPTED

# Strike N1 after the vote
python commissaire.py --action strike_n1 --n1 AF15GH258ZQP
# -> SUCCESS

# Attempt to vote twice
python commissaire.py --action verify_n1 --n1 AF15GH258ZQP
# -> REFUSED : already used (struck out)

# Verify TTH during counting
python commissaire.py --action verify_tth --n2 BK37MN496YRX
# -> VALID

# Display current election state
python commissaire.py --action status
```

### Test results (run during development)

```
Voter 01 : N1=0QE4GL6B39GF  TTH(N2)=889a5129d00485b8...
Voter 02 : N1=BSHZ5R0HW3JI  TTH(N2)=a570fbf05c79f4f7...
Voter 03 : N1=IDP5NWJVSSEU  TTH(N2)=53dc9f26eaf9d559...

verify_n1(0QE4GL6B39GF) -> ACCEPTED
strike_n1(0QE4GL6B39GF) -> SUCCESS : N1 struck out
verify_n1(0QE4GL6B39GF) -> REFUSED : already used (struck out)   [double-vote blocked]
verify_tth(5KS9ME55ZRJM) -> VALID : TTH found in list
```

All four scenarios passed correctly.

---

## 8. Integration with Other Modules

The `Commissioner` class exposes a clean API for `main.py`:

```python
from commissaire import Commissioner

comm = Commissioner()

# --- Called by main.py during initialization ---
comm.initialize(nb_voters=5)

# --- Called by Administrator module ---
if comm.verify_n1(n1):
    # allow voter to proceed

# --- Called by Anonymizer module ---
comm.strike_n1(n1)

# --- Called by Counter module during counting ---
if comm.verify_tth_n2(n2):
    # count the ballot
```

---

## 9. Conclusion

The Commissioner module correctly implements the three security guarantees it is responsible for:

- **Vote uniqueness**: striking out N1 makes double voting technically impossible.
- **N2 confidentiality**: only TTH digests are stored — real N2 values are never retained by the Commissioner.
- **Auditability**: every action is timestamped and logged for post-election auditing.

The separation of responsibilities across the four servers (Commissioner, Administrator, Anonymizer, Counter) is the cornerstone of the protocol: no single server can commit fraud alone, because each one holds only an incomplete view of the system.
