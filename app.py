# -- coding: utf-8 --
# Streamlit wrapper for HashByte backend
# Professional color theming + Matrix rain effect
# Added sidebar (college, organizer, team)

import streamlit as st
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

# ----------------- App config -----------------
st.set_page_config(
    page_title="HashByte - Fake APK Detection",
    layout="wide",
    initial_sidebar_state="expanded"  # sidebar visible by default (visual only)
)

# ----------------- Sidebar (Display Only) -----------------
# ----------------- Sidebar -----------------
with st.sidebar:
    st.image("organizer.png", use_container_width=True)

    st.markdown("### 📌 Submitted by")
    st.write("**Siliguri Institute of Technology**")

    st.markdown("### 👨‍🏫 Guided by")
    st.write("Prof: **Dr. Prasanta Kumar Roy**")
    st.write("📧 prasanta201284@gmail.com")

    st.markdown("### 👥 Team Members")
    team = [
        "Amol Kumar (Leader)",
        "Rohini Kurnari",
        "Bhaskar Kumar",
        "Masuddar Rahaman"
    ]
    for member in team:
        st.write(f"- {member}")


# ----------------- CSS / Theme -----------------
st.markdown(
    """
    <style>
    :root {
        --bg-start: #0a0f0f;
        --bg-end: #091b0b;
        --accent: #00ffa8;
        --accent-2: #05ff66;
        --text: #e6fff2;
        --warn: #ffb84d;
        --err: #ff4d4d;
        --console-bg: rgba(0,0,0,0.82);
        --border: rgba(0,255,168,0.45);
    }
    .stApp {
        background: radial-gradient(1200px 800px at 20% 10%, var(--bg-end), var(--bg-start)) fixed;
        color: var(--text) !important;
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Courier New", monospace;
    }
    .title-glow {
        font-size: 44px !important;
        text-align: center;
        font-weight: 800;
        color: var(--accent);
        text-shadow: 0 0 10px rgba(0,255,168,0.7), 0 0 22px rgba(0,255,168,0.5);
        margin: 6px 0 18px 0;
    }
    .console {
        background: var(--console-bg);
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 12px 14px;
        color: var(--text);
        white-space: pre-wrap;
    }
    .ok { color: var(--accent-2); }
    .err { color: var(--err); }
    .warn { color: var(--warn); }
    div.stButton > button, .stDownloadButton > button {
        background: transparent;
        color: var(--accent);
        border: 1px solid var(--accent);
        border-radius: 10px;
        font-weight: 700;
        padding: 8px 14px;
        transition: all 0.15s ease-in-out;
    }
    div.stButton > button:hover, .stDownloadButton > button:hover {
        background: var(--accent);
        color: #00130a;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown("<div class='title-glow'>🛡 HashByte — Fake APK Detection (Demo)</div>", unsafe_allow_html=True)

# ----------------- Session state init -----------------
for k in ["I", "J", "I_tampered", "private_key", "public_key", "signature", "I_prime", "bank_J", "tampered_bytes"]:
    if k not in st.session_state:
        st.session_state[k] = None

def log(msg, kind="ok"):
    cls = "console"
    if kind == "err":
        st.markdown(f"<div class='{cls} err'>{msg}</div>", unsafe_allow_html=True)
    elif kind == "warn":
        st.markdown(f"<div class='{cls} warn'>{msg}</div>", unsafe_allow_html=True)
    else:
        st.markdown(f"<div class='{cls} ok'>{msg}</div>", unsafe_allow_html=True)

def sha256_hex_file(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

# ----------------- STEP 1 -----------------
st.header("📂 Step 1: Create Dummy APK Files")
st.caption("Here we simulate the initial APK parts (I and J) that will later be validated.")
if st.button("Run Step 1 — Create Files"):
    with open("first_code.bin", "wb") as f:
        f.write(b"This is the First Executable Code of the APK")
    log("[INIT] Dummy First Code created")
    with open("second_code.bin", "wb") as f:
        f.write(b"This is the Second Part of the Code")
    log("[INIT] Dummy Second Code created")
    with open("first_code.bin", "rb") as f:
        st.download_button("⬇ Download first_code.bin", f.read(), file_name="first_code.bin")

# ----------------- STEP 2 -----------------
st.header("🔑 Step 2: APK Server Generates Keys & Signature")
st.caption("The APK Server computes hashes and signs them with its RSA private key.")
if st.button("Run Step 2 — APK Server"):
    st.session_state.I = sha256_hex_file("first_code.bin")
    st.session_state.J = sha256_hex_file("second_code.bin")
    st.session_state.I_tampered = hashlib.sha256(b"This is the First Executable Code of the APK **TAMPERED").hexdigest()
    st.session_state.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    st.session_state.public_key = st.session_state.private_key.public_key()
    with open("public_key.pem", "wb") as f:
        f.write(st.session_state.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    data_to_sign = bytes.fromhex(st.session_state.I) + bytes.fromhex(st.session_state.J)
    st.session_state.signature = st.session_state.private_key.sign(
        data_to_sign,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    with open("signature.bin", "wb") as f:
        f.write(st.session_state.signature)
    log(f"[APK SERVER] I = {st.session_state.I}")
    log(f"[APK SERVER] I_tampered (demo) = {st.session_state.I_tampered}", "warn")
    log("[APK SERVER] Signature created with RSA")
    with open("public_key.pem", "rb") as f:
        st.download_button("⬇ Download public_key.pem", f.read(), file_name="public_key.pem")
    st.download_button("⬇ Download signature.bin", st.session_state.signature, file_name="signature.bin")

# ----------------- STEP 3 -----------------
st.header("👨‍💻 Step 3: 3rd Party Chooses I'")
st.caption("The 3rd party must decide whether to trust the correct or tampered APK hash.")
choice = st.radio("Which I' should 3rd Party trust?", ("Original I (correct)", "Tampered I_tampered (fake)"))
if st.button("Run Step 3 — 3rd Party"):
    if choice.startswith("Tampered"):
        st.session_state.I_prime = st.session_state.I_tampered
        log(f"[3rd PARTY] ❌ Accidentally chose I' = {st.session_state.I_prime}", "warn")
    else:
        with open("first_code.bin", "rb") as f:
            code_3rdparty = f.read()
        st.session_state.I_prime = hashlib.sha256(code_3rdparty).hexdigest()
        log(f"[3rd PARTY] ✅ Computed I' = {st.session_state.I_prime}")
    with open("signature.bin", "rb") as f:
        sig_preview = f.read()[:20]
    log(f"[3rd PARTY] Received Signature (RSA) = {sig_preview} ...")

# ----------------- STEP 4 -----------------
st.header("🏦 Step 4: Bank Verifies I == I'")
st.caption("The bank ensures the APK hash from 3rd party matches its own calculation.")
if st.button("Run Step 4 — Bank Verify"):
    bank_I = sha256_hex_file("first_code.bin")
    if st.session_state.I_prime != bank_I:
        log("❌ Session Expired: Fake APK detected (I != I')", "err")
    else:
        log("[BANK] I == I' verified")
    st.session_state.bank_J = sha256_hex_file("second_code.bin")
    log(f"[BANK] J = {st.session_state.bank_J}")
    with open("second_code.bin", "rb") as f:
        st.download_button("⬇ Download second_code.bin", f.read(), file_name="second_code.bin")

# ----------------- STEP 5 -----------------
st.header("✅ Step 5: Final Verification (RSA)")
st.caption("Finally, the public key is used to validate that signature matches I' + J.")
if st.button("Run Step 5 — Verify"):
    if not st.session_state.I_prime or not st.session_state.bank_J:
        log("Run Steps 3 and 4 first.", "err")
    else:
        data_to_verify = bytes.fromhex(st.session_state.I_prime) + bytes.fromhex(st.session_state.bank_J)
        try:
            with open("public_key.pem", "rb") as f:
                pubkey = serialization.load_pem_public_key(f.read())
            with open("signature.bin", "rb") as f:
                sig = f.read()
            pubkey.verify(sig, data_to_verify,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256())
            log("🎉 Final Application Installed Successfully (RSA verified)")
        except InvalidSignature:
            log("❌ Installation Failed: Invalid Signature", "err")
