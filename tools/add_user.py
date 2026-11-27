"""Give someone a login.

Usage:
  SCC_ADMIN_EMAIL=you@mariarochagroup.com SCC_ADMIN_PASSWORD='...' \\
  SCC_NEW_EMAIL=person@mariarochagroup.com SCC_NEW_PASSWORD='...' python3 tools/add_user.py
An existing login is needed to unlock the private key, which is then re-locked
with the new person's password. Use a long password (12+ characters).
"""
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
from scc_crypto import load_vault, unwrap_user, wrap_for_user, save_json, email_id
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
vp = os.path.join(root, "vault.json"); vault = load_vault(vp)
e = os.environ
if len(e["SCC_NEW_PASSWORD"]) < 12: raise SystemExit("Use a password of 12 characters or more.")
priv = unwrap_user(vault, e["SCC_ADMIN_EMAIL"], e["SCC_ADMIN_PASSWORD"])
h = email_id(e["SCC_NEW_EMAIL"])
vault["users"] = [u for u in vault["users"] if u["h"] != h] + [wrap_for_user(priv, e["SCC_NEW_EMAIL"], e["SCC_NEW_PASSWORD"])]
save_json(vault, vp); print("Login saved for", e["SCC_NEW_EMAIL"])
