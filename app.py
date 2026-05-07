from __future__ import annotations

import json

import streamlit as st

from tth_hash import (
    CODE_LENGTH,
    code_to_numbers,
    create_voter_codes,
    normalize_code,
    public_commissioner_record,
    sha256_fingerprint,
    tth_hash,
    validate_code,
)


st.set_page_config(
    page_title="Student 2 - TTH Hashing",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)


st.markdown(
    """
    <style>
    :root {
        --accent: #2dd4bf;
        --accent-2: #f59e0b;
        --panel: #151a22;
        --border: #2b3442;
    }

    .stApp {
        background: #0b0f14;
        color: #edf2f7;
    }

    .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
        max-width: 1180px;
    }

    h1, h2, h3 {
        letter-spacing: 0;
    }

    [data-testid="stMetric"] {
        background: var(--panel);
        border: 1px solid var(--border);
        border-radius: 8px;
        padding: 1rem;
    }

    div[data-testid="stExpander"] {
        background: var(--panel);
        border: 1px solid var(--border);
        border-radius: 8px;
    }

    .result-box {
        background: var(--panel);
        border: 1px solid var(--border);
        border-left: 4px solid var(--accent);
        border-radius: 8px;
        padding: 1rem;
        margin-top: .75rem;
    }

    .warning-box {
        background: #241b12;
        border: 1px solid #63451d;
        border-left: 4px solid var(--accent-2);
        border-radius: 8px;
        padding: 1rem;
    }

    code {
        color: #a7f3d0;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


def render_code_checker() -> None:
    st.subheader("Hash an N2 Code")
    raw_code = st.text_input(
        "N2 code",
        value="745C4B0KYG3F",
        max_chars=CODE_LENGTH + 6,
        help="Use 12 characters: uppercase letters A-Z and digits 0-9.",
    )
    normalized = normalize_code(raw_code)
    is_valid = validate_code(normalized)

    left, right = st.columns([1, 1])
    with left:
        st.metric("Normalized code", normalized or "empty")
    with right:
        st.metric("Status", "Valid" if is_valid else "Invalid")

    if not is_valid:
        st.markdown(
            f"""
            <div class="warning-box">
            Enter exactly {CODE_LENGTH} characters using only letters and digits.
            Spaces and hyphens are ignored.
            </div>
            """,
            unsafe_allow_html=True,
        )
        return

    numbers = code_to_numbers(normalized)
    tth = tth_hash(normalized)
    sha256_value = sha256_fingerprint(normalized)

    st.markdown(
        f"""
        <div class="result-box">
        <strong>TTH(N2)</strong><br>
        <code>{tth}</code>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col_a, col_b = st.columns([1, 1])
    with col_a:
        st.write("Numeric conversion")
        st.code(" ".join(str(number) for number in numbers), language="text")
    with col_b:
        st.write("SHA-256 comparison")
        st.code(sha256_value, language="text")


def render_generator() -> None:
    st.subheader("Generate Voter Codes")
    count = st.slider("Number of voters", min_value=1, max_value=20, value=5)

    if "records" not in st.session_state:
        st.session_state.records = [create_voter_codes(f"student_{i}") for i in range(1, 6)]

    if st.button("Generate new records", type="primary"):
        st.session_state.records = [
            create_voter_codes(f"student_{i}") for i in range(1, count + 1)
        ]

    records = st.session_state.records
    private_rows = [
        {
            "voter_id": record.voter_id,
            "N1": record.n1,
            "N2_private": record.n2,
            "TTH(N2)": record.tth_n2,
            "SHA256(N2)": record.sha256_n2,
        }
        for record in records
    ]
    public_rows = [public_commissioner_record(record) for record in records]

    tab_private, tab_public, tab_json = st.tabs(
        ["Private demo", "Commissioner data", "JSON export"]
    )
    with tab_private:
        st.dataframe(private_rows, use_container_width=True, hide_index=True)
    with tab_public:
        st.dataframe(public_rows, use_container_width=True, hide_index=True)
    with tab_json:
        export_data = {
            "private_student2_demo": private_rows,
            "public_for_commissioner": public_rows,
        }
        st.code(json.dumps(export_data, indent=2), language="json")
        st.download_button(
            "Download JSON",
            data=json.dumps(export_data, indent=2),
            file_name="student2_hash_demo.json",
            mime="application/json",
        )


def render_protocol_notes() -> None:
    with st.expander("Why this matters in the voting protocol", expanded=True):
        st.write(
            "Student 2 prepares N1 and TTH(N2). The commissioner receives N1 and "
            "TTH(N2), but not the real N2. During counting, a submitted N2 can be "
            "hashed again and compared with the valid fingerprints."
        )
        st.write(
            "The relevant hash property is preimage resistance: knowing TTH(N2) "
            "should not let someone reconstruct the original N2."
        )

st.title("TTH Hashing and Codes")
st.caption("Generate N1/N2 codes and compute TTH(N2).")

render_protocol_notes()
render_code_checker()
render_generator()
