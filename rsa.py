import math
import random

# ─── Key generation ──────────────────────────────────────────────
def is_prime(n):
    if n < 2: return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0: return False
    return True

def generate_prime(bits=8):
    """Generate a small prime (for demo purposes)."""
    while True:
        n = random.randrange(2**(bits-1), 2**bits)
        if is_prime(n):
            return n

def extended_gcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x, y = extended_gcd(b, a % b)
    return g, y, x - (a // b) * y

def mod_inverse(a, m):
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        raise ValueError("Inverse doesn't exist")
    return x % m

def generate_keypair(p, q):
    """Generate RSA public and private keys from primes p and q."""
    N = p * q
    phi = (p - 1) * (q - 1)
    # Choose e coprime to phi
    e = 3
    while math.gcd(e, phi) != 1:
        e += 2
    d = mod_inverse(e, phi)
    return (e, N), (d, N)

# ─── Encrypt / Decrypt ───────────────────────────────────────────
def encrypt(message: int, public_key: tuple) -> int:
    e, N = public_key
    return pow(message, e, N)

def decrypt(ciphertext: int, private_key: tuple) -> int:
    d, N = private_key
    return pow(ciphertext, d, N)

# ─── RSA Signature ───────────────────────────────────────────────
def sign(message: int, private_key: tuple) -> int:
    """Sign a message with the private key."""
    d, N = private_key
    return pow(message, d, N)

def verify(message: int, signature: int, public_key: tuple) -> bool:
    """Verify a signature with the public key."""
    e, N = public_key
    return pow(signature, e, N) == message

# ─── Blind Signature ─────────────────────────────────────────────
def blind_message(message: int, k: int, public_key: tuple) -> int:
    """Alice masks the message before sending to Bob."""
    e, N = public_key
    return (message * pow(k, e, N)) % N

def blind_sign(blinded_message: int, private_key: tuple) -> int:
    """Bob signs the blinded message (without seeing the original)."""
    d, N = private_key
    return pow(blinded_message, d, N)

def unblind(blind_signature: int, k: int, N: int) -> int:
    """Alice removes the mask to get the real signature."""
    k_inv = mod_inverse(k, N)
    return (blind_signature * k_inv) % N

# ─── Demo ────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Exercise 2 values
    N, e, d = 55, 27, 3
    pub = (e, N)
    priv = (d, N)

    print("=== Exercise 2 Demo ===")
    print(f"Public key: (e={e}, N={N}), Private key: d={d}")

    m = 4
    k = 2
    print(f"\nMessage: m = {m}, Masking factor: k = {k}")

    m_prime = blind_message(m, k, pub)
    print(f"Blinded message m' = {m_prime}")

    m_double_prime = blind_sign(m_prime, priv)
    print(f"Bob's blind signature m'' = {m_double_prime}")

    s = unblind(m_double_prime, k, N)
    print(f"Unblinded signature s = {s}")

    valid = verify(m, s, pub)
    print(f"Signature valid? {valid}  (s^e mod N = {pow(s, e, N)}, should be {m})")

    # Larger key generation demo
    print("\n=== Key generation demo ===")
    p, q = 11, 53   # 583 = counter's N from exercise 4
    pub2, priv2 = generate_keypair(p, q)
    print(f"p={p}, q={q} → N={p*q}, phi={p*q - p - q + 1}")
    print(f"Public key: {pub2}")
    print(f"Private key: {priv2}")
    msg = 7
    enc = encrypt(msg, pub2)
    dec = decrypt(enc, priv2)
    print(f"Encrypt {msg} → {enc} → Decrypt → {dec}")
    assert dec == msg, "Decryption failed!"
    print("All checks passed.")