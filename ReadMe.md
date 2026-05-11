#  Electronic Voting System

A secure electronic voting system built with Python and Streamlit that simulates a complete cryptographic voting protocol using RSA encryption, blind signatures, vote anonymization, and secure vote counting.

---

##  Live Demo

👉 https://crypto-voting-20-26-f.streamlit.app/

---

##  GitHub Repository

👉 https://github.com/jazia-abdelkrim/crypto_voting

---

# 📌 Project Overview

This project simulates a secure electronic voting process inspired by real-world cryptographic voting systems.

The system guarantees:

-  Only authorized voters can vote
-  Votes remain confidential
-  Voter anonymity is preserved
-  Double voting is prevented
-  Ballots are digitally signed

---

#  System Components

| Component | Role |
|---|---|
| Commissioner | Generates voter credentials |
| Admin Server | Verifies voter rights and signs ballots |
| Anonymizer Server | Removes voter identity traces |
| Counter | Decrypts and counts votes |

---

#  Cryptographic Concepts Used

## RSA Encryption

Used for:

- Vote encryption
- Digital signatures
- Secure communication

---

## Blind Signature Protocol

Allows the Admin to sign ballots without seeing the actual vote content, preserving voter privacy.

---

## Hashing (TTH)

Used to securely verify voter codes without exposing sensitive information.

---

#  Features

-  Secure voter authentication
-  Encrypted ballots
-  Blind signature implementation
-  Anonymous vote submission
-  Secure vote tallying
-  Double-vote prevention
-  Interactive Streamlit interface

---

#  Project Structure

```bash
crypto_voting/
│
├── app.py
├── main.py
├── admin.py
├── anonymiseur.py
├── commissioner.py
├── decompte.py
├── tth_hash.py
├── requirements.txt
└── README.md
```

---

#  Installation

Clone the repository:

```bash
git clone https://github.com/jazia-abdelkrim/crypto_voting.git
cd crypto_voting
```

Create a virtual environment (recommended):

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

#  Run the Application

```bash
streamlit run app.py
```

or:

```bash
python3 -m streamlit run app.py
```

---

# 🖥️ Example Workflow

1. Commissioner generates voter codes
2. Admin verifies voter identity
3. Voter blinds the ballot
4. Admin signs the blinded ballot
5. Vote is encrypted
6. Anonymizer removes identity traces
7. Counter decrypts and counts votes
8. Final results are displayed

---

#  Double Voting Protection

The system prevents a voter from voting multiple times by invalidating used voter credentials after submission.

---

#  Technologies Used

- Python 3
- Streamlit
- RSA Cryptography
- Hash Functions
- Object-Oriented Programming

---

#  Educational Purpose

This project was developed for educational purposes to demonstrate:

- Electronic voting systems
- Applied cryptography
- RSA encryption
- Blind signatures
- Secure authentication protocols


# 📜 License

This project is intended for academic and educational use.
