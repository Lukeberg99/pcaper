"""PCAPER — upload WiFi handshake captures and submit them for cracking.

Upload `.pcap`, `.pcapng` or `.cap` files (one or many at once). Captures can be
sent to OnlineHashCrack (converted to Hashcat mode 22000 hashes), to Stanev
wpa-sec (raw capture upload), or to both services in a single action.

API keys are read from Streamlit secrets / environment as optional defaults, or
entered in the sidebar per session.
"""
from __future__ import annotations

import os
import tempfile

import streamlit as st

import pcap_converter
from ohc_client import OHCClient, OHCError
from stanev_client import StanevClient, StanevError

ALLOWED_EXTENSIONS = ("pcap", "pcapng", "cap")

DEST_OHC = "OnlineHashCrack"
DEST_STANEV = "Stanev (wpa-sec)"
DEST_BOTH = "Both"


def _secret_or_env(name: str, default: str = "") -> str:
    try:
        if name in st.secrets:
            return str(st.secrets[name])
    except Exception:
        pass
    return os.environ.get(name, default)


def get_default_ohc_key() -> str:
    return _secret_or_env("OHC_API_KEY")


def get_default_stanev_key() -> str:
    return _secret_or_env("STANEV_API_KEY")


def get_api_url() -> str:
    return _secret_or_env("OHC_API_URL", "https://api.onlinehashcrack.com/v2")


def get_stanev_url() -> str:
    return _secret_or_env("STANEV_API_URL", "https://wpa-sec.stanev.org")


def make_ohc_client(api_key: str) -> OHCClient:
    return OHCClient(api_key=api_key, base_url=get_api_url())


def make_stanev_client(api_key: str) -> StanevClient:
    return StanevClient(api_key=api_key, base_url=get_stanev_url())


def needs_ohc(destination: str) -> bool:
    return destination in (DEST_OHC, DEST_BOTH)


def needs_stanev(destination: str) -> bool:
    return destination in (DEST_STANEV, DEST_BOTH)


def convert_files(files) -> tuple[list[dict], list[str]]:
    """Convert uploaded captures for OHC. Returns per-file rows and unique hashes."""
    per_file: list[dict] = []
    all_hashes: list[str] = []

    with st.status("Converting captures for OnlineHashCrack…", expanded=True) as status:
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

        seen: set[str] = set()
        unique = [h for h in all_hashes if not (h in seen or seen.add(h))]
        status.update(label="Conversion done", state="complete")

    return per_file, unique


def submit_to_stanev(client: StanevClient, files) -> list[dict]:
    items = [(f.name, bytes(f.getbuffer())) for f in files]
    with st.spinner(f"Uploading {len(items)} file(s) to Stanev…"):
        return client.upload_many(items)


st.set_page_config(page_title="PCAPER → HashCrack", page_icon="📡", layout="centered")
st.title("📡 PCAPER")
st.caption(
    "Upload one or many handshake captures and submit them to OnlineHashCrack, "
    "Stanev (wpa-sec), or both."
)

with st.sidebar:
    st.header("Settings")
    destination = st.radio(
        "Submit to",
        options=[DEST_OHC, DEST_STANEV, DEST_BOTH],
        help=(
            "OnlineHashCrack receives Hashcat mode 22000 hashes. "
            "Stanev receives the raw capture files."
        ),
    )
    st.divider()
    ohc_key = st.text_input(
        "OnlineHashCrack API key",
        value=get_default_ohc_key(),
        type="password",
        placeholder="sk_...",
        help="Required when submitting to OnlineHashCrack or Both.",
    ).strip()
    st.caption("Get a key at onlinehashcrack.com → API Key management.")
    stanev_key = st.text_input(
        "Stanev (wpa-sec) key",
        value=get_default_stanev_key(),
        type="password",
        placeholder="your wpa-sec key",
        help="Required when submitting to Stanev or Both. Get one at wpa-sec.stanev.org.",
    ).strip()

tool_ok = pcap_converter.is_available()
ohc_key_ok = bool(ohc_key)
stanev_key_ok = bool(stanev_key)
submit_ohc = needs_ohc(destination)
submit_stanev = needs_stanev(destination)

if submit_ohc and not tool_ok:
    st.error(
        "`hcxpcapngtool` is not installed. On Streamlit Cloud / Hugging Face Spaces "
        "this is provided by `packages.txt` (hcxtools). Locally: "
        "`sudo apt-get install hcxtools`."
    )
if submit_ohc and not ohc_key_ok:
    st.info("Enter your OnlineHashCrack API key in the sidebar.")
if submit_stanev and not stanev_key_ok:
    st.info("Enter your Stanev (wpa-sec) key in the sidebar.")

can_submit = bool(
    submit_ohc is False or (tool_ok and ohc_key_ok)
) and bool(submit_stanev is False or stanev_key_ok)

tab_upload, tab_tasks = st.tabs(["Upload & submit", "My OHC tasks"])

with tab_upload:
    files = st.file_uploader(
        "Capture files",
        type=list(ALLOWED_EXTENSIONS),
        accept_multiple_files=True,
        help="Select one or many .pcap, .pcapng or .cap WiFi captures.",
    )

    if files:
        st.caption(f"{len(files)} file(s) selected.")

    submit = st.button(
        "Convert & submit" if submit_ohc else "Upload captures",
        type="primary",
        disabled=not (can_submit and files),
    )

    if submit and files:
        conversion_rows: list[dict] = []
        unique_hashes: list[str] = []

        if submit_ohc:
            conversion_rows, unique_hashes = convert_files(files)
            st.subheader("Conversion (OnlineHashCrack)")
            st.dataframe(conversion_rows, use_container_width=True, hide_index=True)

            if not unique_hashes:
                st.warning(
                    "No valid handshake or PMKID was found for OnlineHashCrack, "
                    "so nothing was submitted there."
                )
            else:
                with st.spinner(
                    f"Submitting {len(unique_hashes)} hash(es) to OnlineHashCrack…"
                ):
                    try:
                        result = make_ohc_client(ohc_key).chunk_and_submit(
                            unique_hashes, pcap_converter.ALGO_MODE
                        )
                    except OHCError as exc:
                        st.error(f"OnlineHashCrack submission failed: {exc}")
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
                    st.success("OnlineHashCrack submission complete.")

        if submit_stanev:
            st.subheader("Upload (Stanev)")
            try:
                stanev_results = submit_to_stanev(make_stanev_client(stanev_key), files)
            except StanevError as exc:
                st.error(f"Stanev upload failed: {exc}")
                stanev_results = None

            if stanev_results:
                st.dataframe(
                    [
                        {
                            "File": row["filename"],
                            "Status": row["status"],
                            "Response": row["message"],
                        }
                        for row in stanev_results
                    ],
                    use_container_width=True,
                    hide_index=True,
                )
                accepted = sum(1 for row in stanev_results if row["status"] == "accepted")
                duplicates = sum(1 for row in stanev_results if row["status"] == "duplicate")
                c1, c2 = st.columns(2)
                c1.metric("Uploaded", accepted)
                c2.metric("Already submitted", duplicates)
                st.success(
                    f"Stanev upload complete ({len(stanev_results)} file(s) processed)."
                )
                st.caption(
                    "View cracked handshakes at "
                    "[wpa-sec.stanev.org](https://wpa-sec.stanev.org/) with your key."
                )

with tab_tasks:
    if st.button("Refresh tasks", disabled=not ohc_key_ok):
        st.session_state["_refresh_tasks"] = True
    if ohc_key_ok:
        try:
            data = make_ohc_client(ohc_key).list_tasks()
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
                st.info("No OnlineHashCrack tasks yet.")
        except OHCError as exc:
            st.error(str(exc))
    else:
        st.info("Configure the OnlineHashCrack API key to list your tasks.")

st.divider()
st.caption("Use restricted to handshakes you own or are authorized to test.")
