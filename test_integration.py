
import math
from admin import AdminServer
from anonymiseur import AnonymizerServer

ADMIN_N, ADMIN_E, ADMIN_D = 55, 27, 3
COUNTER_N, COUNTER_E = 583, 3

admin = AdminServer(ADMIN_E, ADMIN_N, ADMIN_D)
anonymizer = AnonymizerServer()

VALID_N1_LIST = ["AF15GH258ZQP", "BK37MN496YRX", "TEST001CODE123"]
admin.load_valid_n1(VALID_N1_LIST)

print(" Keys Loaded |  N1 List Ready\n")

def simulate_voter(n1, vote_value, n2_code):
    print(f"--- Voter starts: N1={n1}, Vote={vote_value} ---")
    
    if not admin.check_voter_right(n1):
        print(" Admin: Voting rights denied\n")
        return False

    m = (vote_value * 1000 + int(n2_code[:2])) % ADMIN_N
    print(f"  Ballot message (m) = {m}")

    k = 2
    while math.gcd(k, ADMIN_N) != 1:
        k += 1

    m_masked = (m * pow(k, ADMIN_E, ADMIN_N)) % ADMIN_N
    print(f" Voter sends masked m' = {m_masked}")

    m_double_prime = admin.blind_sign(m_masked)
    print(f"  Admin returns signed m'' = {m_double_prime}")

    k_inv = pow(k, -1, ADMIN_N)
    signature = (m_double_prime * k_inv) % ADMIN_N
    print(f" Voter obtains final signature s = {signature}")

    verified = pow(signature, ADMIN_E, ADMIN_N) == m % ADMIN_N
    print(f" Signature Verification: {'PASSED' if verified else 'FAILED'}")

    encrypted_vote = pow(vote_value, COUNTER_E, COUNTER_N)
    print(f" Vote encrypted: {encrypted_vote}")

    success, msg = anonymizer.receive_vote(n1, encrypted_vote, signature, set(admin.valid_n1))
    print(f" Anonymizer: {msg}\n")
    return success


simulate_voter("AF15GH258ZQP", 7, "14")
simulate_voter("BK37MN496YRX", 9, "22")
simulate_voter("AF15GH258ZQP", 5, "99")  

print(" Final Anonymous Ballot Box:")
for i, ballot in enumerate(anonymizer.get_ballots_for_counter(), 1):
    print(f"Ballot {i}: Encrypted={ballot['encrypted_vote']}, Sig={ballot['signature']}")