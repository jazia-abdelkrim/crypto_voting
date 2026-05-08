
class AnonymizerServer:
    def __init__(self):
        self.ballot_box = []      
        self.used_n1 = set()      

    def receive_vote(self, n1, encrypted_vote, signature, commissioner_valid_n1):
      
        if n1 not in commissioner_valid_n1 or n1 in self.used_n1:
            return False, " Invalid or already used N1 code."

        self.used_n1.add(n1)
        commissioner_valid_n1.discard(n1)

        self.ballot_box.append({
            "encrypted_vote": encrypted_vote,
            "signature": signature
        })
        return True, " Vote successfully stored in the anonymous ballot box."

    def get_ballots_for_counter(self):
        return self.ballot_box