# 🛰️ C2 Server – Malware Evasion TFG

This folder contains the implementation of the Command and Control (C2) server used in the TFG project. The server is responsible for serving the payload, DLLs, and receiving communications from the malware sample.

---

## 📁 Contents

- `server.py`: Flask-based HTTP server that handles:
  - Payload delivery
  - DLL delivery (camouflaged as images)
  - Session validation via hash
- `payload.enc`: RC4-encrypted and Base64-encoded PowerShell payload.
- `favicon.ico`: DLL used for DLL proxying, disguised as an icon file.
- `index.html`: Contains the encrypted payload with added steganographic HTML header.
- `hash.txt`: Contains the SHA-256 hash of the dropper binary for session validation.

---

## 🚀 How It Works

1. **Session Validation**  
   The malware sends a GET request to `/session` with a cookie containing its SHA-256 hash.  
   If the hash matches `hash.txt`, the server responds with `200 OK`.

2. **Payload Delivery**  
   The malware requests `/index.html`, which returns the encrypted payload (`payload.enc`) with a fake HTML header.  
   The RC4 key is embedded in the `Server` HTTP header (e.g., `nginx/supersecreta`).

3. **DLL Delivery**  
   - `/image.png`: Returns the stub DLL used for reflective loading.
   - `/favicon.ico`: Returns the DLL used for DLL proxying.

---

## 🛠️ Requirements

- Python 3.x
- Flask

Install dependencies:

```bash
pip install flask

