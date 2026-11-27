"""Replace the key pair (after removing someone, or once a year).

Usage: SCC_USERS='a@x.com:pass1,b@x.com:pass2' SCC_ADMIN_EMAIL=... SCC_ADMIN_PASSWORD=... python3 tools/rotate_keys.py
Re-locks app.enc.json and data.enc.json with a new key pair and gives logins
only to the people listed in SCC_USERS.
"""
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
from scc_crypto import load_vault, unwrap_user, new_keypair, wrap_for_user, seal, open_box, save_json, b64, ITER
import json
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
vp = os.path.join(root, "vault.json"); vault = load_vault(vp); e = os.environ
old = unwrap_user(vault, e["SCC_ADMIN_EMAIL"], e["SCC_ADMIN_PASSWORD"])
pub, priv = new_keypair()
for name in ("app.enc.json", "data.enc.json"):
    p = os.path.join(root, name); save_json(seal(open_box(json.load(open(p)), old), pub), p)
users = [x.split(":", 1) for x in e["SCC_USERS"].split(",") if x]
save_json({"v": 1, "iter": ITER, "pub": b64(pub), "users": [wrap_for_user(priv, m, pw) for m, pw in users]}, vp)
print("Keys rotated for", len(users), "users")
