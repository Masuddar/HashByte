import streamlit as st
import hashlib
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

# ----------------- Page Config -----------------
st.set_page_config(
    page_title="HashByte — Frontend (Step-by-step)",
    layout="wide",
    initial_sidebar_state="expanded"
)

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
        font-size: 40px !important;
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
        margin-bottom: 8px;
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

# ----------------- Title -----------------
st.markdown("<div class='title-glow'>🛡 Virtual Demonstration of APK Security</div>", unsafe_allow_html=True)
st.caption("Step-by-step workflow of Fake APK Detection (Frontend Demo)")

# ---------------- session state -----------------
for k in [
    "I", "J", "I_tampered", "private_key_obj", "public_key_bytes",
    "signature", "tampered_signature", "I_prime", "bank_J"
]:
    if k not in st.session_state:
        st.session_state[k] = None

# ---------------- helper functions -----------------
def sha256_hex_file(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

def file_exists_warn(path: str) -> bool:
    if not os.path.exists(path):
        st.markdown(f"<div class='console warn'>⚠ File not found: {path}. Run the earlier step first.</div>", unsafe_allow_html=True)
        return False
    return True

def log(msg, kind="ok"):
    cls = "console"
    if kind == "err":
        st.markdown(f"<div class='{cls} err'>{msg}</div>", unsafe_allow_html=True)
    elif kind == "warn":
        st.markdown(f"<div class='{cls} warn'>{msg}</div>", unsafe_allow_html=True)
    else:
        st.markdown(f"<div class='{cls} ok'>{msg}</div>", unsafe_allow_html=True)


# ---------------- Stage 1 ----------------
st.header("Create dummy APK files for verification")
if st.button("Create & Check Files"):
    with open("first_code.bin", "wb") as f:
        f.write(b"This is the First Executable Code of the APK")
    st.success("Created first_code.bin - contains (I)")

    with open("second_code.bin", "wb") as f:
        f.write(b"This is the Second Part of the Code")
    st.success("Created second_code.bin - contains (J)")

    # quick downloads
    with open("first_code.bin", "rb") as f:
        st.download_button("⬇ Download first_code.bin", f.read(), file_name="first_code.bin")
    with open("second_code.bin", "rb") as f:
        st.download_button("⬇ Download second_code.bin", f.read(), file_name="second_code.bin")

# ---------------- Stage 2 ----------------
st.header("Generating hashes, keys, signatures and a tampered signature for demo")
if st.button("Generate & Check"):
    if not file_exists_warn("first_code.bin") or not file_exists_warn("second_code.bin"):
        st.error("Step 1 must be run first.")
    else:
        st.session_state.I = sha256_hex_file("first_code.bin")
        st.session_state.J = sha256_hex_file("second_code.bin")

        st.session_state.I_tampered = hashlib.sha256(
            b"This is the First Executable Code of the APK **TAMPERED"
        ).hexdigest()

        private_key_obj = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        st.session_state.private_key_obj = private_key_obj
        public_key = private_key_obj.public_key()

        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        st.session_state.public_key_bytes = public_bytes
        with open("public_key.pem", "wb") as f:
            f.write(public_bytes)

        data_to_sign = bytes.fromhex(st.session_state.I) + bytes.fromhex(st.session_state.J)
        signature = private_key_obj.sign(
            data_to_sign,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        st.session_state.signature = signature
        with open("signature.bin", "wb") as f:
            f.write(signature)

        tampered_sig = bytearray(signature)
        tampered_sig[0] ^= 0xFF
        st.session_state.tampered_signature = bytes(tampered_sig)
        with open("tampered_signature.bin", "wb") as f:
            f.write(st.session_state.tampered_signature)

        st.success(f"[APK SERVER] I = {st.session_state.I}")
        st.warning(f"[APK SERVER] I_tampered (demo) = {st.session_state.I_tampered}")
        st.info("Public key + signatures written to disk.")

        with open("public_key.pem", "rb") as f:
            st.download_button("⬇ Download public_key.pem", f.read(), file_name="public_key.pem")
        st.download_button("⬇ Download signature.bin (original)", st.session_state.signature, file_name="signature.bin")
        st.download_button("⬇ Download tampered_signature.bin (fake)", st.session_state.tampered_signature, file_name="tampered_signature.bin")

# ---------------- Stage 3 ----------------
st.header("3rd Party computes or chooses a tampered I'")
choice = st.radio("Which I' should the 3rd party use?", ("Compute from first_code.bin (correct)", "Use Tampered I_tampered (fake)"))
if st.button("Choose I'"):
    if choice.startswith("Use Tampered"):
        if st.session_state.I_tampered is None:
            st.error("Run Step 2 first to generate the tampered demo hash.")
        else:
            st.session_state.I_prime = st.session_state.I_tampered
            st.warning(f"[3rd PARTY] Tempered I' = {st.session_state.I_prime}")
    else:
        if not file_exists_warn("first_code.bin"):
            st.error("first_code.bin missing — run Step 1 first.")
        else:
            with open("first_code.bin", "rb") as f:
                code_3rdparty = f.read()
            st.session_state.I_prime = hashlib.sha256(code_3rdparty).hexdigest()
            st.success(f"[3rd PARTY] Computed I' = {st.session_state.I_prime}")

    if os.path.exists("signature.bin"):
        with open("signature.bin", "rb") as f:
            sig_preview = f.read(40)
        st.write("[3rd PARTY] Received signature preview (first 40 bytes):")
        st.code(sig_preview.hex())
    else:
        st.info("signature.bin not found yet — run Step 2.")

# ---------------- Stage 4 ----------------
st.header("Bank Verification of I == I'")
if st.button("Verify"):
    if st.session_state.I_prime is None:
        st.error("I' not computed — run Step 3 first.")
        st.stop()

    if not file_exists_warn("first_code.bin"):
        st.error("first_code.bin missing — run Step 1 first.")
        st.stop()

    bank_I = sha256_hex_file("first_code.bin")
    if st.session_state.I_prime != bank_I:
        st.error(" Session Expired: Fake APK detected (I != I')")
        st.session_state.bank_J = None
        st.stop()
    else:
        st.success("[BANK] I == I' verified")
        st.session_state.bank_J = sha256_hex_file("second_code.bin")
        st.info(f"[BANK] J = {st.session_state.bank_J}")
        with open("second_code.bin", "rb") as f:
            st.download_button("⬇ Download second_code.bin", f.read(), file_name="second_code.bin")

# ---------------- Stage 5 ----------------
st.header("Final Verification (RSA)")
sig_choice = st.radio("Which Signature should be used?", ("Original signature.bin", "Tampered tampered_signature.bin"))

if st.button("Run Step 5 — Verify"):
    if not st.session_state.I_prime or not st.session_state.bank_J:
        st.error("Run Steps 3 and 4 before final verification.")
    else:
        sig = st.session_state.signature if sig_choice.startswith("Original") else st.session_state.tampered_signature
        if sig is None:
            st.error("No signature found. Run Step 2 (APK Server) first.")
        else:
            # Append I' + J
            data_to_verify = bytes.fromhex(st.session_state.I_prime) + bytes.fromhex(st.session_state.bank_J)

            try:
                with open("public_key.pem", "rb") as f:
                    pubkey = serialization.load_pem_public_key(f.read())

                pubkey.verify(
                    sig,
                    data_to_verify,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )

                # If signature matches
                if sig_choice.startswith("Original"):
                    st.success("RSA Verification Passed")
                    st.success("Installation Successful – Key & Signature Verified")
                else:
                    # Even if verify() passes, choosing tampered should trigger fake APK warning
                    st.error("Installation Failed – Fake APK Detected")
                    st.warning("⚠ Tampered signature chosen. APK integrity compromised.")

            except InvalidSignature:
                st.error("Signature/Key verification failed")
                st.warning("⚠ Installation Failed – Fake APK (Signature mismatch).")

            except Exception as e:
                st.error(f"⚠ Verification error: {e}")


# ---------------- Stage 6 ----------------
st.header("Compare signed data (bank's I+J) vs (computed I'+J)")
if st.button("Compare"):
    if st.session_state.I is None or st.session_state.J is None:
        st.error("Missing canonical I/J (run Step 2 first).")
    elif st.session_state.I_prime is None or st.session_state.bank_J is None:
        st.error("Missing I' or bank_J (run Steps 3 & 4 first).")
    else:
        data_to_verify = bytes.fromhex(st.session_state.I_prime) + bytes.fromhex(st.session_state.bank_J)
        data_to_sign = bytes.fromhex(st.session_state.I) + bytes.fromhex(st.session_state.J)
        if data_to_verify == data_to_sign:
            st.success("Verification Successful Allpication can be installed")
        else:
            st.error("Verification Failed Application cannot be installed")

st.markdown("---")

st.write("Copyright © 2025 HashByte Demo. All rights reserved.")
