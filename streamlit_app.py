"""PCAPER — upload WiFi handshake captures and submit them to OnlineHashCrack.

Upload `.pcap`, `.pcapng` or `.cap` files. Each capture is converted to Hashcat
mode 22000 (WPA-PBKDF2-PMKID+EAPOL) hashes with hcxpcapngtool, then submitted
automatically to the OnlineHashCrack private API.

The API key is read from Streamlit secrets / environment and never shown to the
user, per OHC's implementation best practices.
"""
from __future__ import annotations

import os
import tempfile

import streamlit as st

import pcap_converter
from ohc_client import OHCClient, OHCError

ALLOWED_EXTENSIONS = ("pcap", "pcapng", "cap")


def get_default_api_key() -> str:
    """Optional default OHC API key from Streamlit secrets / env.

    On a public, multi-user deployment leave these unset so each user enters
    their own key in the sidebar. If set, it just pre-fills the input.
    """
    try:
        if "OHC_API_KEY" in st.secrets:
            return str(st.secrets["OHC_API_KEY"])
    except Exception:
        # st.secrets raises if no secrets file exists; fall back to env.
        pass
    return os.environ.get("OHC_API_KEY", "")


def get_api_url() -> str:
    try:
        if "OHC_API_URL" in st.secrets:
            return str(st.secrets["OHC_API_URL"])
    except Exception:
        pass
    return os.environ.get("OHC_API_URL", "https://api.onlinehashcrack.com/v2")


def make_client(api_key: str) -> OHCClient:
    return OHCClient(api_key=api_key, base_url=get_api_url())


st.set_page_config(page_title="PCAPER → HashCrack", page_icon="📡", layout="centered")
st.title("📡 PCAPER")
st.caption(
    "Upload handshake captures, auto-convert to Hashcat mode "
    f"{pcap_converter.ALGO_MODE} (WPA-PBKDF2-PMKID+EAPOL), and submit to "
    "OnlineHashCrack."
)

with st.sidebar:
    st.header("Settings")
    api_key = st.text_input(
        "OnlineHashCrack API key",
        value=get_default_api_key(),
        type="password",
        placeholder="sk_...",
        help=(
            "Your personal OHC key (format sk_...). It is used only for your "
            "requests in this session and is never stored or shared."
        ),
    ).strip()
    st.caption("Get a key at onlinehashcrack.com → API Key management.")

tool_ok = pcap_converter.is_available()
key_ok = bool(api_key)

if not tool_ok:
    st.error(
        "`hcxpcapngtool` is not installed. On Streamlit Cloud this is provided "
        "by `packages.txt` (hcxtools). Locally: `sudo apt-get install hcxtools`."
    )
if not key_ok:
    st.info("Enter your OnlineHashCrack API key in the sidebar to begin.")

tab_upload, tab_tasks = st.tabs(["Upload & submit", "My tasks"])

with tab_upload:
    files = st.file_uploader(
        "Capture files",
        type=list(ALLOWED_EXTENSIONS),
        accept_multiple_files=True,
        help="Accepts .pcap, .pcapng and .cap WiFi captures.",
    )

    submit = st.button(
        "Convert & submit",
        type="primary",
        disabled=not (tool_ok and key_ok and files),
    )

    if submit and files:
        per_file = []
        all_hashes: list[str] = []

        with st.status("Converting captures…", expanded=True) as status:
            for f in files:
                suffix = "." + f.name.rsplit(".", 1)[-1].lower()
                with tempfile.NamedTemporaryFile(suffix=suffix, delete=True) as tmp:
                    tmp.write(f.getbuffer())
                    tmp.flush()
                    try:
                        hashes, _stderr = pcap_converter.convert_to_hashes(tmp.name)
                    except pcap_converter.ConversionError as exc:
                        per_file.append({"File": f.name, "Hashes": 0, "Note": str(exc)})
                        st.write(f"❌ {f.name}: {exc}")
                        continue
                note = "ok" if hashes else "no handshake/PMKID found"
                icon = "✅" if hashes else "⚠️"
                per_file.append({"File": f.name, "Hashes": len(hashes), "Note": note})
                st.write(f"{icon} {f.name}: {len(hashes)} hash(es)")
                all_hashes.extend(hashes)

            # De-duplicate across all files.
            seen: set[str] = set()
            unique = [h for h in all_hashes if not (h in seen or seen.add(h))]
            status.update(label="Conversion done", state="complete")

        st.subheader("Files processed")
        st.dataframe(per_file, use_container_width=True, hide_index=True)

        if not unique:
            st.warning(
                "No valid handshake or PMKID was found, so nothing was submitted."
            )
        else:
            with st.spinner(f"Submitting {len(unique)} hash(es) to OnlineHashCrack…"):
                try:
                    result = make_client(api_key).chunk_and_submit(
                        unique, pcap_converter.ALGO_MODE
                    )
                except OHCError as exc:
                    st.error(f"Submission failed: {exc}")
                    result = None

            if result:
                c1, c2, c3 = st.columns(3)
                c1.metric("Accepted", result["accepted"]["count"])
                c2.metric("Skipped", result["skipped"]["count"])
                c3.metric("Rejected", result["rejected"]["count"])
                if result["skipped"]["count"] and result["skipped"]["reason"]:
                    st.info(f"Skipped reason: {result['skipped']['reason']}")
                if result["rejected"]["count"] and result["rejected"]["reason"]:
                    st.warning(f"Rejected reason: {result['rejected']['reason']}")
                if result["request_ids"]:
                    st.caption("request_id(s): " + ", ".join(result["request_ids"]))
                st.success("Done. Check the 'My tasks' tab for status.")

with tab_tasks:
    if st.button("Refresh tasks", disabled=not key_ok):
        st.session_state["_refresh_tasks"] = True
    if key_ok:
        try:
            data = make_client(api_key).list_tasks()
            tasks = data.get("tasks", [])
            if tasks:
                st.dataframe(
                    [
                        {
                            "Created": t.get("created_at", ""),
                            "Hash": (t.get("hash", "")[:24] + "…")
                            if len(t.get("hash", "")) > 24
                            else t.get("hash", ""),
                            "Algorithm": f"{t.get('algorithm', '')} ({t.get('algomode', '')})",
                            "Status": t.get("status", ""),
                            "Last attack": t.get("lastAttack", ""),
                        }
                        for t in tasks
                    ],
                    use_container_width=True,
                    hide_index=True,
                )
            else:
                st.info("No tasks yet.")
        except OHCError as exc:
            st.error(str(exc))
    else:
        st.info("Configure the API key to list your tasks.")

st.divider()
st.caption("Use restricted to handshakes you own or are authorized to test.")
