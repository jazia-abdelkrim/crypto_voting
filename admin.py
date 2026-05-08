
import math

class AdminServer:
    def __init__(self, e, N, d):

        self.public_key = (e, N)
        self.private_key = d
        self.valid_n1 = set()

    def load_valid_n1(self, n1_list):

        self.valid_n1 = set(n1_list)

    def check_voter_right(self, n1):

        return n1 in self.valid_n1

    def blind_sign(self, m_masked):
 
        N = self.public_key[1]
        return pow(m_masked, self.private_key, N)