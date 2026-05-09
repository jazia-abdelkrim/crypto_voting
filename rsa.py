import math
import random


# aretmetic functions

def is_prime(n: int) -> bool:
    """Check if n is a prime number."""
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    for i in range(3, int(n**0.5) + 1, 2):
        if n % i == 0:
            return False
    return True


def extended_gcd(a: int, b: int) -> tuple:
    """
    Extended Euclidean Algorithm.
    Returns (gcd, x, y) such that: a*x + b*y = gcd(a, b)
    """
    if b == 0:
        return a, 1, 0
    gcd, x, y = extended_gcd(b, a % b)
    return gcd, y, x - (a // b) * y


def mod_inverse(a: int, m: int) -> int:
    """
    Compute the modular inverse of a modulo m.
    Returns x such that: a * x = 1 (mod m)
    Uses the Extended Euclidean Algorithm.
    """
    gcd, x, _ = extended_gcd(a % m, m)
    if gcd != 1:
        raise ValueError(f"Modular inverse does not exist: gcd({a}, {m}) = {gcd} != 1")
    return x % m


def generate_prime_in_range(low: int, high: int) -> int:
    """Generate a random prime number between low and high."""
    candidates = list(range(low, high + 1))
    random.shuffle(candidates)
    for n in candidates:
        if is_prime(n):
            return n
    raise ValueError(f"No prime found in range [{low}, {high}]")



# RSA key generation 


def generate_keypair(p: int, q: int) -> tuple:
     """
    Generate an RSA key pair from two prime numbers p and q.
 
    Steps:
        1. Compute N = p * q
        2. Compute phi(N) = (p-1)(q-1)
        3. Choose e such that gcd(e, phi(N)) = 1
        4. Compute d = e^(-1) mod phi(N)
 
    Returns:
        public_key  : (e, N)
        private_key : (d, N)
    """
    if not is_prime(p):
        raise ValueError(f"p={p} is not prime")
    if not is_prime(q):
        raise ValueError(f"q={q} is not prime")
    if p == q:
        raise ValueError("p and q must be different primes")

    N = p * q
    phi_N = (p - 1) * (q - 1)

    # Choose e: start from 3, find first value coprime with phi_N
    e = 3
    while math.gcd(e, phi_N) != 1:
        e += 2

    # Compute private key d
    d = mod_inverse(e, phi_N)

    return (e, N), (d, N)


def keypair_from_exercise2() -> tuple:
    """
    Return the fixed key pair from Exercise 2:
        N = 55 = 5 x 11
        e = 27  (given)
        d = 3   (computed: 27*3 = 81 = 2*40+1 => 81 mod 40 = 1)
    """
    return (27, 55), (3, 55)



# RSA encryption


def encrypt(message: int, public_key: tuple) -> int:
    """
    Encrypt a message using RSA public key.
    Formula: ciphertext = message^e mod N
    """
    e, N = public_key
    if message < 0 or message >= N:
        raise ValueError(f"Message must be in range [0, N-1]. Got {message}, N={N}")
    return pow(message, e, N)


# RSA decryption


def decrypt(ciphertext: int, private_key: tuple) -> int:
    """
    Decrypt a ciphertext using RSA private key.
    Formula: message = ciphertext^d mod N
    """
    d, N = private_key
    return pow(ciphertext, d, N)



# RSA digital signature

def sign(message: int, private_key: tuple) -> int:
    """
    Sign a message with the private key.
    Formula: signature = message^d mod N
    (Signing = encrypting with private key)
    """
    d, N = private_key
    return pow(message, d, N)


def verify_signature(message: int, signature: int, public_key: tuple) -> bool:
    """
    Verify a signature with the public key.
    Check: signature^e mod N == message
    (Verification = encrypting with public key and comparing)
    """
    e, N = public_key
    return pow(signature, e, N) == message



# blind signature

def blind_message(message: int, k: int, public_key: tuple) -> int:
    """
    Alice blinds the message before sending to Bob (the Admin).
    Formula: m' = m * k^e mod N

    Bob cannot determine m because he does not know k.

    Args:
        message    : the original message m (the ballot)
        k          : blinding factor, must satisfy gcd(k, N) = 1
        public_key : Bob's public key (e, N)

    Returns:
        m' : the blinded message
    """
    e, N = public_key
    if math.gcd(k, N) != 1:
        raise ValueError(f"Blinding factor k={k} must be coprime with N={N}")
    return (message * pow(k, e, N)) % N


def blind_sign(blinded_message: int, private_key: tuple) -> int:
    """
    Bob (Admin) signs the blinded message without knowing the original.
    Formula: m'' = (m')^d mod N

    Args:
        blinded_message : m' received from Alice
        private_key     : Bob's private key (d, N)

    Returns:
        m'' : the blind signature
    """
    d, N = private_key
    return pow(blinded_message, d, N)


def unblind_signature(blind_sig: int, k: int, N: int) -> int:
    """
    Alice removes the blinding factor to obtain the real signature.
    Formula: s = m'' * k^(-1) mod N

    After unblinding: s = m^d mod N  (valid RSA signature of m)

    Args:
        blind_sig : m'' returned by Bob
        k         : the blinding factor Alice chose
        N         : RSA modulus

    Returns:
        s : the valid RSA signature of the original message m
    """
    k_inv = mod_inverse(k, N)
    return (blind_sig * k_inv) % N


def full_blind_signature_protocol(message: int, k: int,
                                   public_key: tuple, private_key: tuple) -> dict:
    """
    Run the complete blind signature protocol (Exercise 2).

    Returns a dictionary with all intermediate values for inspection.
    """
    e, N = public_key
    d, _ = private_key

    # Step 1: Alice blinds the message
    m_prime = blind_message(message, k, public_key)

    # Step 2: Bob signs the blinded message
    m_double_prime = blind_sign(m_prime, private_key)

    # Step 3: Alice unblinds to get the real signature
    s = unblind_signature(m_double_prime, k, N)

    # Step 4: Verify the signature
    valid = verify_signature(message, s, public_key)

    return {
        "message (m)": message,
        "blinding_factor (k)": k,
        "k^e mod N": pow(k, e, N),
        "blinded_message (m')": m_prime,
        "blind_signature (m'')": m_double_prime,
        "k_inverse (k^-1 mod N)": mod_inverse(k, N),
        "final_signature (s)": s,
        "verification (s^e mod N)": pow(s, e, N),
        "signature_valid": valid,
    }



# proof of blind signature validity (exo1)

def proof_of_blind_signature():
    """
    Proof that s = m'' / k (mod N) is a valid RSA signature of m.

    To verify RSA signature (m, s), we must show: s^e = m (mod N)

    Proof:
        s  = m'' * k^(-1)           (mod N)         [definition of division mod N]
           = (m')^d * k^(-1)        (mod N)         [since m'' = (m')^d mod N]
           = (m * k^e)^d * k^(-1)   (mod N)         [since m' = m * k^e mod N]
           = m^d * k^(e*d) * k^(-1) (mod N)         [expand the power]

        By RSA theorem: e*d = 1 (mod phi(N))
        Therefore: k^(e*d) = k^1 = k  (mod N)       [Euler's theorem]

           = m^d * k * k^(-1)       (mod N)         [substitute]
           = m^d                    (mod N)          [k * k^(-1) = 1]

        Therefore: s = m^d (mod N)  <-- this is the RSA signature of m

        Verification: s^e = (m^d)^e = m^(d*e) = m^1 = m (mod N)  QED
    """
    return proof_of_blind_signature.__doc__



# DEMO

def run_exercise2_demo():
    """Demonstrate Exercise 2 with N=55, e=27, d=3."""
    print("=" * 60)
    print("EXERCISE 2 - Blind Signature Demo (N=55, e=27, d=3)")
    print("=" * 60)

    pub, priv = keypair_from_exercise2()
    e, N = pub
    d, _ = priv

    print(f"  Public key  : (e={e}, N={N})")
    print(f"  Private key : (d={d}, N={N})")
    print(f"  phi(N)      : (5-1)*(11-1) = 40")
    print(f"  Verify d    : {e}*{d} = {e*d} = {e*d // 40}*40+{e*d % 40} => {e*d % 40} (mod 40) ✓")

    message = 4
    k = 2
    print(f"\n  Message m = {message}, Blinding factor k = {k}")
    print(f"  gcd({k}, {N}) = {math.gcd(k, N)} ✓ (k is valid)")

    result = full_blind_signature_protocol(message, k, pub, priv)

    print(f"\n  Step 1 - Alice blinds the message:")
    print(f"    k^e mod N = {k}^{e} mod {N} = {result['k^e mod N']}")
    m_prime = result["blinded_message (m')"]
    m_pp    = result["blind_signature (m'')"]
    k_inv   = result["k_inverse (k^-1 mod N)"]
    s       = result["final_signature (s)"]

    print(f"    m' = m * k^e mod N = {message} * {result['k^e mod N']} mod {N} = {m_prime}")

    print(f"\n  Step 2 - Bob signs (without knowing m={message}):")
    print(f"    m'' = (m')^d mod N = {m_prime}^{d} mod {N} = {m_pp}")

    print(f"\n  Step 3 - Alice unblinds:")
    print(f"    k^(-1) mod N = {k_inv}  [since {k}*{k_inv} mod {N} = {k * k_inv % N}]")
    print(f"    s = m'' * k^(-1) mod N = {m_pp} * {k_inv} mod {N} = {s}")

    print(f"\n  Step 4 - Verification:")
    print(f"    s^e mod N = {s}^{e} mod {N} = {result['verification (s^e mod N)']}")
    print(f"    Expected m = {message}")
    print(f"    Signature valid? {result['signature_valid']} {'✓' if result['signature_valid'] else '✗'}")


def run_exercise4_demo():
    """Demonstrate Exercise 4: vote encryption with counter key (e=3, N=583)."""
    print("\n" + "=" * 60)
    print("EXERCISE 4 - Vote Encryption (Counter key: e=3, N=583)")
    print("=" * 60)

    counter_pub = (3, 583)
    # Find d for counter: N=583=11*53, phi=(10)(52)=520, 3*d=1 mod 520
    counter_priv = (mod_inverse(3, 520), 583)
    d2 = counter_priv[0]

    print(f"  Counter public key : (e=3, N=583)")
    print(f"  583 = 11 * 53  =>  phi(583) = 10*52 = 520")
    print(f"  Counter private key: d = {d2}  [3*{d2}={3*d2}, {3*d2} mod 520 = {3*d2 % 520}] ✓")

    vote = 7
    encrypted = encrypt(vote, counter_pub)
    decrypted = decrypt(encrypted, counter_priv)

    print(f"\n  Vote = {vote}")
    print(f"  Encrypted vote = {vote}^3 mod 583 = {encrypted}")
    print(f"  Decrypted vote = {encrypted}^{d2} mod 583 = {decrypted}")
    print(f"  Correct? {decrypted == vote} ✓")


def run_keygen_demo():
    """Demonstrate key generation from scratch."""
    print("\n" + "=" * 60)
    print("KEY GENERATION DEMO (automatic)")
    print("=" * 60)

    p, q = 11, 53
    pub, priv = generate_keypair(p, q)
    e, N = pub
    d, _ = priv

    print(f"  Primes: p={p}, q={q}")
    print(f"  N = {p}*{q} = {N}")
    print(f"  phi(N) = ({p}-1)*({q}-1) = {(p-1)*(q-1)}")
    print(f"  Public key  : (e={e}, N={N})")
    print(f"  Private key : (d={d}, N={N})")
    print(f"  Verify: e*d mod phi = {e}*{d} mod {(p-1)*(q-1)} = {e*d % ((p-1)*(q-1))} ✓")

    msg = 42
    c = encrypt(msg, pub)
    m = decrypt(c, priv)
    print(f"\n  Encrypt {msg} -> {c} -> Decrypt -> {m}  {'✓' if m == msg else '✗'}")

    sig = sign(msg, priv)
    ok = verify_signature(msg, sig, pub)
    print(f"  Sign {msg} -> {sig} -> Verify -> {ok}  {'✓' if ok else '✗'}")



# MAIN

if __name__ == "__main__":
    print("\nRSA Implementation - ENSTA Alger - Student 1")
    print("Project: Cryptography Applied to Electronic Voting\n")

    run_exercise2_demo()
    run_exercise4_demo()
    run_keygen_demo()

    print("\n" + "=" * 60)
    print("PROOF (Exercise 1) - Summary")
    print("=" * 60)
    print("  s = m^d mod N  (valid RSA signature of m)")
    print("  Because k^(e*d) = k (by Euler's theorem), the")
    print("  blinding factor k cancels out perfectly when")
    print("  Alice removes the mask, leaving s = m^d mod N.")
    print("  Verification: s^e mod N = m  QED")
    print("\nAll done.")
