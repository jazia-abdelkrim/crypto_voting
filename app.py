from __future__ import annotations

import json
import math
import hashlib
import secrets
import string
import streamlit as st


# Page config


st.set_page_config(
    page_title="CryptoVote — ENSTA Alger",
    page_icon="🗳️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
:root {
    --green:  #8BD600;
    --teal:   #2dd4bf;
    --amber:  #f59e0b;
    --red:    #ef4444;
    --panel:  #151a22;
    --border: #2b3442;
    --bg:     #0b0f14;
    --text:   #edf2f7;
    --muted:  #94a3b8;
}
.stApp { background: var(--bg); color: var(--text); }
.block-container { padding-top: 1.5rem; max-width: 1280px; }
h1,h2,h3 { letter-spacing: -.02em; }

/* metric cards */
[data-testid="stMetric"] {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 1rem 1.2rem;
}

/* expander */
div[data-testid="stExpander"] {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
}

/* custom boxes */
.info-box {
    background: var(--panel);
    border: 1px solid var(--border);
    border-left: 4px solid var(--teal);
    border-radius: 8px;
    padding: .9rem 1rem;
    margin-bottom: .75rem;
}
.success-box {
    background: #0f2217;
    border: 1px solid #1a4731;
    border-left: 4px solid var(--green);
    border-radius: 8px;
    padding: .9rem 1rem;
    margin-bottom: .75rem;
}
.error-box {
    background: #200e0e;
    border: 1px solid #5c2020;
    border-left: 4px solid var(--red);
    border-radius: 8px;
    padding: .9rem 1rem;
    margin-bottom: .75rem;
}
.warn-box {
    background: #241b12;
    border: 1px solid #63451d;
    border-left: 4px solid var(--amber);
    border-radius: 8px;
    padding: .9rem 1rem;
    margin-bottom: .75rem;
}
.step-card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 1rem 1.2rem;
    margin-bottom: .6rem;
}
code { color: #a7f3d0; }
</style>
""", unsafe_allow_html=True)



# RSA helpers (Student 1)


ADMIN_E, ADMIN_N, ADMIN_D = 27, 55, 3
COUNTER_E, COUNTER_N      = 3, 583
CODE_ALPHABET = string.ascii_uppercase + string.digits
CODE_LENGTH   = 12


def _gcd(a, b):
    while b: a, b = b, a % b
    return a


def _mod_inv(a, m):
    g, x = m, 0
    a0, m0 = a % m, m
    x0, x1 = 0, 1
    if m == 1: return 0
    while a0 > 1:
        q = a0 // m
        m, a0 = a0 % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 % m0


def rsa_encrypt(m, e, N): return pow(m, e, N)
def rsa_decrypt(c, d, N): return pow(c, d, N)
def rsa_sign(m, d, N):    return pow(m, d, N)
def rsa_verify(m, s, e, N): return pow(s, e, N) == m % N


def blind_protocol(message, k, e, N, d):
    k_e   = pow(k, e, N)
    m_p   = (message * k_e) % N
    m_pp  = pow(m_p, d, N)
    k_inv = _mod_inv(k, N)
    s     = (m_pp * k_inv) % N
    return {"m": message, "k": k, "k^e": k_e, "m'": m_p, "m''": m_pp, "k^-1": k_inv, "s": s,
            "verified": pow(s, e, N) == message % N}



# TTH helpers (Student 2)


def generate_code():
    return "".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LENGTH))


def normalize_code(code):
    return code.replace(" ", "").replace("-", "").upper()


def validate_code(code):
    return len(code) == CODE_LENGTH and all(c in CODE_ALPHABET for c in code)


def char_to_number(c):
    return int(c) if c.isdigit() else ord(c) - ord("A") + 1


def tth_hash(code):
    values = [char_to_number(c) for c in code]
    while len(values) < 16:
        values.append((values[-1] + len(values) + 7) % 27)
    state = [3, 5, 7, 11]
    for i, v in enumerate(values[:16]):
        sl = i % 4
        nb = state[(sl - 1) % 4]
        state[sl] = (state[sl] + v + nb * (i + 1)) % 97
    return "TTH-" + "-".join(f"{p:02X}" for p in state)


def sha256_fingerprint(code):
    return hashlib.sha256(code.encode()).hexdigest()


def create_voter(voter_id):
    n1 = generate_code()
    n2 = generate_code()
    return {"voter_id": voter_id, "n1": n1, "n2": n2,
            "tth_n2": tth_hash(n2), "sha256_n2": sha256_fingerprint(n2)}



# Voting helpers (Students 3-5)


def build_message(vote_val, n2_str):
    try: n2_num = int(str(n2_str)[:2])
    except: n2_num = 0
    return (vote_val * 1000 + n2_num) % ADMIN_N


def simulate_full_vote(voters, vote_assignments):
    """
    Run the full protocol for each voter.
    Returns list of ballot records + tally.
    """
    # Commissioner state
    n1_list   = {v["n1"]: "valid" for v in voters}
    tth_list  = [v["tth_n2"] for v in voters]
    used_n1   = set()
    ballot_box = []
    log = []

    for voter, vote_val in zip(voters, vote_assignments):
        n1, n2 = voter["n1"], voter["n2"]
        vid    = voter["voter_id"]
        entry  = {"voter_id": vid, "vote": vote_val, "steps": []}

        # 1 – N1 check
        if n1_list.get(n1) != "valid" or n1 in used_n1:
            entry["steps"].append({"label": "N1 check", "status": "❌ denied"})
            entry["result"] = "rejected"
            log.append(entry)
            continue
        entry["steps"].append({"label": "N1 check", "status": " approved"})

        # 2 – build message
        m = build_message(vote_val, n2)
        entry["steps"].append({"label": f"Ballot message m = {m}", "status": "📄"})

        # 3 – blind signature
        k = 2
        while _gcd(k, ADMIN_N) != 1: k += 1
        proto = blind_protocol(m, k, ADMIN_E, ADMIN_N, ADMIN_D)
        sig = proto["s"]
        entry["steps"].append({"label": f"Blind sign → s = {sig}", "status": " valid" if proto["verified"] else " invalid"})

        # 4 – encrypt
        enc = rsa_encrypt(vote_val, COUNTER_E, COUNTER_N)
        entry["steps"].append({"label": f"Encrypted vote = {enc}", "status": "🔒"})

        # 5 – anonymizer
        n1_list[n1] = "struck"
        used_n1.add(n1)
        ballot_box.append({"enc_vote": enc, "sig": sig, "n2": n2, "voter_id": vid})
        entry["steps"].append({"label": "Deposited in ballot box", "status": "🗳️ anonymous"})
        entry["result"] = "counted"
        log.append(entry)

    # Tally
    tally = {}
    audit = []
    for b in ballot_box:
        dec_vote = rsa_decrypt(b["enc_vote"], 347, COUNTER_N)  # d=347
        m_check  = build_message(dec_vote, b["n2"])
        sig_ok   = rsa_verify(m_check, b["sig"], ADMIN_E, ADMIN_N)
        tth_ok   = tth_hash(b["n2"]) in tth_list
        if sig_ok and tth_ok:
            tally[dec_vote] = tally.get(dec_vote, 0) + 1
            audit.append({**b, "decrypted": dec_vote, "valid": True})
        else:
            audit.append({**b, "decrypted": dec_vote, "valid": False})

    return log, tally, audit



# Session state init


def _init():
    if "voters" not in st.session_state:
        st.session_state.voters = []
    if "vote_log" not in st.session_state:
        st.session_state.vote_log = []
    if "tally" not in st.session_state:
        st.session_state.tally = {}
    if "audit" not in st.session_state:
        st.session_state.audit = []
    if "election_done" not in st.session_state:
        st.session_state.election_done = False

_init()



# Sidebar


with st.sidebar:
    st.markdown("## 🗳️ CryptoVote")
    st.caption("ENSTA Alger · Ms. KHERROUBI · 2026")
    st.divider()
    page = st.radio(
        "Navigation",
        [" Overview", " RSA & Blind Sig", " TTH Hashing",
         " Live Election", " Results & Audit"],
        label_visibility="collapsed",
    )
    st.divider()
    st.caption("**Keys in use**")
    st.code(f"Admin:   e={ADMIN_E}, N={ADMIN_N}, d={ADMIN_D}", language="text")
    st.code(f"Counter: e={COUNTER_E}, N={COUNTER_N}", language="text")



# PAGE 1 — Overview


if page == " Overview":
    st.title("Cryptography Applied to Electronic Voting")
    st.caption("ENSTA Alger · Applied Cryptography Project · February 2026")

    st.markdown("""
    <div class="info-box">
    This dashboard demonstrates a <strong>complete secure electronic voting system</strong>
    built from first principles: RSA encryption, blind signatures, and TTH hashing.
    Navigate with the sidebar to explore each component, or jump straight to <em>Live Election</em>.
    </div>
    """, unsafe_allow_html=True)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("RSA modules", "N=55, N=583")
    c2.metric("Code length", "12 chars")
    c3.metric("Possible codes", "≈ 4.7 × 10¹⁸")
    c4.metric("Servers", "4 independent")

    st.divider()
    st.subheader("Protocol Flow")

    cols = st.columns(4)
    steps = [
        ("1️⃣ Commissioner", "Generates N1/N2 pairs. Stores only TTH(N2). Destroys real N2."),
        ("2️⃣ Administrator", "Verifies N1 identity. Blind-signs the ballot — never sees content."),
        ("3️⃣ Anonymizer", "Accepts encrypted+signed ballots. Strips voter identity."),
        ("4️⃣ Counter", "Decrypts, verifies signatures+TTH, tallies. Cannot link to voter."),
    ]
    for col, (title, desc) in zip(cols, steps):
        with col:
            st.markdown(f"""
            <div class="step-card">
            <strong>{title}</strong><br><br>
            <span style="color:var(--muted);font-size:.85rem">{desc}</span>
            </div>""", unsafe_allow_html=True)

    st.divider()
    st.subheader("Why Each Server Cannot Cheat")

    rows = [
        ("Commissioner", "Knows N1 list + TTH(N2) only. Cannot create valid ballots (no N2, no Admin key)."),
        ("Administrator", "Sees only the *masked* ballot — blind signature means zero content knowledge."),
        ("Anonymizer",    "Receives encrypted vote only. Cannot read it (no Counter private key)."),
        ("Counter",       "Reads votes after polls close. Cannot link a vote to a voter (no N1 data)."),
    ]
    for entity, reason in rows:
        st.markdown(f"""
        <div class="step-card">
        <strong>{entity}</strong> — {reason}
        </div>""", unsafe_allow_html=True)


# ─────────────────────────────────────────────
# PAGE 2 — RSA & Blind Signature
# ─────────────────────────────────────────────

elif page == " RSA & Blind Sig":
    st.title("RSA & Blind Signature — Student 1")

    tab_ex1, tab_ex2, tab_ex4 = st.tabs(["Exercise 1 — Proof", "Exercise 2 — Demo", "Exercise 4 — Vote"])

    with tab_ex1:
        st.subheader("Proof: s = m''/k (mod N) is a valid RSA signature")
        st.markdown("""
        **Goal:** show that `s^e ≡ m (mod N)` where `s = m'' · k⁻¹ mod N`.

        ```
        s  = m'' · k⁻¹             (mod N)
           = (m')^d · k⁻¹          (mod N)   [since m'' = (m')^d]
           = (m · k^e)^d · k⁻¹     (mod N)   [since m' = m · k^e]
           = m^d · k^(ed) · k⁻¹    (mod N)
        ```
        By the RSA theorem: `ed ≡ 1 (mod φ(N))`, so `k^(ed) ≡ k (mod N)` (Euler).
        ```
           = m^d · k · k⁻¹         (mod N)
           = m^d                   (mod N)   ✓
        ```
        Therefore `s = m^d mod N` — the valid RSA signature of `m`. **QED.**
        """)

    with tab_ex2:
        st.subheader("Exercise 2 — Blind Signature with N=55, e=27, d=3")
        st.markdown("**φ(55) = (5−1)(11−1) = 40** · **27·3 = 81 = 2·40+1 ≡ 1 (mod 40) ✓**")

        col_l, col_r = st.columns(2)
        with col_l:
            m_val = st.number_input("Message m (voter's ballot)", min_value=0, max_value=54, value=4)
        with col_r:
            k_val = st.number_input("Blinding factor k", min_value=2, max_value=54, value=2)

        if _gcd(int(k_val), ADMIN_N) != 1:
            st.markdown('<div class="warn-box">k must be coprime with N=55. Try another value.</div>', unsafe_allow_html=True)
        else:
            p = blind_protocol(int(m_val), int(k_val), ADMIN_E, ADMIN_N, ADMIN_D)
            p_ke, p_mp, p_mpp = p["k^e"], p["m'"], p["m''"]
            p_kinv, p_s = p["k^-1"], p["s"]
            rows = [
                ("k^e mod N",              f"{k_val}^{ADMIN_E} mod {ADMIN_N}",                      p_ke),
                ("Blinded message m'",     f"{m_val} x {p_ke} mod {ADMIN_N}",                       p_mp),
                ("Blind signature m''",    f"(m')^d mod N = ({p_mp})^{ADMIN_D} mod {ADMIN_N}",     p_mpp),
                ("k^-1 mod N",            f"inverse of {k_val} mod {ADMIN_N}",                      p_kinv),
                ("Final signature s",      f"m'' x k^-1 mod N = {p_mpp} x {p_kinv} mod {ADMIN_N}", p_s),
                ("Verification s^e mod N", f"{p_s}^{ADMIN_E} mod {ADMIN_N}",                        pow(p_s, ADMIN_E, ADMIN_N)),
            ]
            df_data = [{"Step": r[0], "Formula": r[1], "Result": r[2]} for r in rows]
            st.dataframe(df_data, use_container_width=True, hide_index=True)
            box = "success-box" if p["verified"] else "error-box"
            icon = "" if p["verified"] else ""
            st.markdown(f'<div class="{box}">{icon} Signature valid: s^e mod N = {pow(p["s"],ADMIN_E,ADMIN_N)} = m = {m_val}</div>', unsafe_allow_html=True)

    with tab_ex4:
        st.subheader("Exercise 4 — Vote Encryption (Counter key e=3, N=583)")
        st.markdown("**583 = 11 × 53** → **φ(583) = 10 × 52 = 520** → **d = 347** (3·347 = 1041 ≡ 1 mod 520)")
        vote_ex4 = st.slider("Vote value", 0, 10, 7)
        enc4 = rsa_encrypt(vote_ex4, COUNTER_E, COUNTER_N)
        dec4 = rsa_decrypt(enc4, 347, COUNTER_N)
        c1, c2, c3 = st.columns(3)
        c1.metric("Original vote", vote_ex4)
        c2.metric(f"Encrypted = {vote_ex4}³ mod 583", enc4)
        c3.metric(f"Decrypted = {enc4}^347 mod 583", dec4)
        if dec4 == vote_ex4:
            st.markdown('<div class="success-box"> Encryption → Decryption round-trip verified!</div>', unsafe_allow_html=True)



# PAGE 3 — TTH Hashing


elif page == " TTH Hashing":
    st.title("TTH Hashing & Voter Codes — Student 2")

    tab_hash, tab_gen = st.tabs(["Hash a Code", "Generate Voter Codes"])

    with tab_hash:
        st.subheader("Compute TTH(N2)")
        raw = st.text_input("Enter an N2 code", value="BK37MN496YRX", max_chars=CODE_LENGTH + 6)
        norm = normalize_code(raw)
        valid = validate_code(norm)
        c1, c2 = st.columns(2)
        c1.metric("Normalized", norm or "empty")
        c2.metric("Status", "Valid " if valid else "Invalid ")

        if valid:
            tth = tth_hash(norm)
            sha = sha256_fingerprint(norm)
            nums = [char_to_number(c) for c in norm]
            st.markdown(f'<div class="success-box"><strong>TTH(N2)</strong><br><code>{tth}</code></div>', unsafe_allow_html=True)
            col_a, col_b = st.columns(2)
            with col_a:
                st.write("Numeric conversion")
                st.code(" ".join(str(n) for n in nums), language="text")
            with col_b:
                st.write("SHA-256 (reference)")
                st.code(sha, language="text")

            st.markdown("""
            <div class="info-box">
            <strong>Preimage resistance</strong>: Given <code>TTH(N2)</code>, it is computationally
            infeasible to recover <code>N2</code>. The Commissioner can verify votes without
            ever knowing the real N2.
            </div>""", unsafe_allow_html=True)
        else:
            st.markdown(f'<div class="warn-box">Enter exactly {CODE_LENGTH} alphanumeric uppercase characters.</div>', unsafe_allow_html=True)

    with tab_gen:
        st.subheader("Generate Voter Codes")
        n_voters = st.slider("Number of voters", 1, 15, 5)
        if st.button("Generate new codes", type="primary"):
            st.session_state["tth_records"] = [create_voter(f"voter_{i:02d}") for i in range(1, n_voters + 1)]

        records = st.session_state.get("tth_records", [create_voter(f"voter_{i:02d}") for i in range(1, 6)])

        tab_priv, tab_pub, tab_json = st.tabs(["Private (demo)", "Commissioner data", "JSON"])
        with tab_priv:
            st.dataframe(
                [{"voter_id": r["voter_id"], "N1": r["n1"], "N2 (private)": r["n2"],
                  "TTH(N2)": r["tth_n2"], "SHA256(N2)": r["sha256_n2"][:24] + "..."} for r in records],
                use_container_width=True, hide_index=True,
            )
        with tab_pub:
            st.dataframe(
                [{"voter_id": r["voter_id"], "N1": r["n1"], "TTH(N2)": r["tth_n2"]} for r in records],
                use_container_width=True, hide_index=True,
            )
        with tab_json:
            export = {"private_demo": records, "public_for_commissioner": [
                {"voter_id": r["voter_id"], "n1": r["n1"], "tth_n2": r["tth_n2"]} for r in records
            ]}
            st.code(json.dumps(export, indent=2), language="json")
            st.download_button("⬇ Download JSON", data=json.dumps(export, indent=2),
                               file_name="voter_codes.json", mime="application/json")



# PAGE 4 — Live Election


elif page == " Live Election":
    st.title("Live Election Simulation")

    st.markdown("""
    <div class="info-box">
    Configure your election below. Click <strong>Run Election</strong> to simulate the full protocol:
    code generation → blind signing → encryption → anonymization → tallying.
    </div>""", unsafe_allow_html=True)

    with st.form("election_form"):
        nb = st.slider("Number of voters", 1, 10, 5)
        votes_input = st.text_input(
            "Vote values (comma-separated integers, one per voter)",
            value="7, 8, 7, 9, 7",
            help="e.g. '7, 8, 7' for 3 voters"
        )
        attack = st.checkbox("Simulate double-vote attack by voter 1", value=True)
        submitted = st.form_submit_button("🗳️ Run Election", type="primary")

    if submitted:
        try:
            raw_votes = [int(v.strip()) for v in votes_input.split(",")]
        except ValueError:
            st.error("Vote values must be integers separated by commas.")
            st.stop()

        # Pad / trim vote list
        while len(raw_votes) < nb: raw_votes.append(raw_votes[-1])
        vote_values = raw_votes[:nb]

        # Generate voter codes
        voters = [create_voter(f"voter_{i:02d}") for i in range(1, nb + 1)]
        st.session_state.voters = voters

        with st.spinner("Running the full cryptographic protocol..."):
            log, tally, audit = simulate_full_vote(voters, vote_values)

        st.session_state.vote_log      = log
        st.session_state.tally         = tally
        st.session_state.audit         = audit
        st.session_state.election_done = True

        # ── Results preview ───────────────────────────────────────────────────
        st.success("Election complete! See the Results & Audit page for full details.")

        st.subheader("Quick Results")
        if tally:
            cols = st.columns(len(tally))
            for col, (v, c) in zip(cols, sorted(tally.items())):
                col.metric(f"Vote = {v}", f"{c} vote{'s' if c>1 else ''}")
        else:
            st.warning("No valid votes counted.")

        # ── Step log ─────────────────────────────────────────────────────────
        st.subheader("Protocol Trace")
        for entry in log:
            with st.expander(f"{entry['voter_id']}  →  vote={entry['vote']}  [{entry.get('result','—')}]",
                             expanded=False):
                for step in entry.get("steps", []):
                    st.markdown(f"- {step['status']}  **{step['label']}**")

        # ── Double-vote test ─────────────────────────────────────────────────
        if attack and voters:
            st.subheader(" Double-Vote Attack")
            v0 = voters[0]
            # Commissioner already struck N1, so Anonymizer will reject
            used = {v0["n1"]}
            fake_ballot_box = []
            enc = rsa_encrypt(vote_values[0], COUNTER_E, COUNTER_N)
            m   = build_message(vote_values[0], v0["n2"])
            k   = 2
            while _gcd(k, ADMIN_N) != 1: k += 1
            proto = blind_protocol(m, k, ADMIN_E, ADMIN_N, ADMIN_D)
            n1_state = {"valid": set(), "struck": {v0["n1"]}}

            # Simulate anonymizer check
            blocked = v0["n1"] in used
            icon    = " BLOCKED" if blocked else " PASSED (bug!)"
            st.markdown(f'<div class="{"success-box" if blocked else "error-box"}">'
                        f'{icon}: Re-vote attempt by {v0["voter_id"]} was {"rejected by Anonymizer" if blocked else "accepted — error!"}'
                        f'</div>', unsafe_allow_html=True)

    elif not st.session_state.election_done:
        st.info("Configure the election above and click **Run Election** to begin.")



# PAGE 5 — Results & Audit


elif page == " Results & Audit":
    st.title("Results & Public Audit")

    if not st.session_state.election_done:
        st.markdown('<div class="warn-box">No election has been run yet. Go to <strong>Live Election</strong> first.</div>', unsafe_allow_html=True)
        st.stop()

    tally  = st.session_state.tally
    audit  = st.session_state.audit
    voters = st.session_state.voters

    # ── Tally ─────────────────────────────────────────────────────────────────
    st.subheader("Tally")
    total_valid = sum(tally.values())
    c1, c2, c3 = st.columns(3)
    c1.metric("Valid votes", total_valid)
    c2.metric("Rejected",    len(audit) - total_valid)
    c3.metric("Total ballots", len(audit))

    if tally:
        winner = max(tally, key=tally.get)
        st.markdown(f'<div class="success-box"> Most popular vote: <strong>{winner}</strong> ({tally[winner]} vote(s))</div>', unsafe_allow_html=True)
        bars = {str(k): v for k, v in sorted(tally.items())}
        st.bar_chart(bars, color="#8BD600")
    else:
        st.warning("No valid votes to display.")

    # ── Audit log ─────────────────────────────────────────────────────────────
    st.subheader("Public Audit Log")
    st.markdown("""
    <div class="info-box">
    Each row below is publicly verifiable. Any voter who knows their own <code>N2</code>
    can find their row and confirm their vote was counted correctly.
    </div>""", unsafe_allow_html=True)

    audit_rows = []
    for i, b in enumerate(audit, 1):
        audit_rows.append({
            "#":           i,
            "N2 (public)": b["n2"],
            "Encrypted":   b["enc_vote"],
            "Decrypted":   b["decrypted"],
            "Sig valid":   "" if b["valid"] else "",
            "Status":      "counted" if b["valid"] else "rejected",
        })
    st.dataframe(audit_rows, use_container_width=True, hide_index=True)

    # ── JSON export ───────────────────────────────────────────────────────────
    st.subheader("Export")
    export = {
        "tally":     tally,
        "audit_log": audit,
        "voters_public": [{"voter_id": v["voter_id"], "n1": v["n1"], "tth_n2": v["tth_n2"]} for v in voters],
    }
    st.download_button(
        "⬇ Download full audit JSON",
        data=json.dumps(export, indent=2, default=str),
        file_name="election_audit.json",
        mime="application/json",
    )