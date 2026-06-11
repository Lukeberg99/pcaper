# PCAPER

A simple **Streamlit** app to upload WiFi handshake captures (`.pcap`,
`.pcapng`, `.cap`), convert them to Hashcat **mode 22000**
(WPA-PBKDF2-PMKID+EAPOL) hashes with
[`hcxpcapngtool`](https://github.com/ZerBea/hcxtools), and submit them
automatically to the [OnlineHashCrack](https://onlinehashcrack.com) private API.

> Use is strictly limited to handshakes you own or are authorized to test.

## Features

- Upload one or many capture files at once.
- Server-side conversion to mode 22000 hashes (PMKID + EAPOL), de-duplicated.
- Automatic submission to OHC (`add_tasks`), batched at 50 hashes/request.
- Accepted / skipped / rejected metrics plus `request_id`s.
- "My tasks" tab listing your OHC tasks (`list_tasks`).
- The API key stays **server-side** (Streamlit secrets) — never shown in the UI.

## Deploy on Streamlit Community Cloud

1. Push this repo to GitHub (already done if you're reading this there).
2. Go to <https://share.streamlit.io/new>.
3. Pick this repo, branch `main`, main file `streamlit_app.py`.
4. Open **Advanced settings → Secrets** and paste:
   ```toml
   OHC_API_KEY = "sk_your_key_here"
   ```
5. Deploy. The `packages.txt` file makes Streamlit Cloud install `hcxtools`
   (which provides `hcxpcapngtool`) automatically.

## Run locally

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# hcxpcapngtool (Debian/Ubuntu):
sudo apt-get install -y hcxtools   # macOS: brew install hcxtools

# secrets:
cp .streamlit/secrets.toml.example .streamlit/secrets.toml
# edit and set OHC_API_KEY=sk_...

streamlit run streamlit_app.py
```

## Configuration

| Secret / env var | Required | Description                                   |
|------------------|----------|-----------------------------------------------|
| `OHC_API_KEY`    | yes      | Your `sk_...` OnlineHashCrack private API key. |
| `OHC_API_URL`    | no       | API base endpoint (defaults to the v2 URL).    |

## Notes

- Mode 22000 hashes are extracted only when the capture contains a valid PMKID
  or a complete EAPOL handshake. If none is found, nothing is submitted.
- The OHC API accepts up to 50 hashes per request; larger sets are chunked.
- Respect the API per-key hourly rate limit.
