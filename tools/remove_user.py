"""Remove someone's login.

Usage: python3 tools/remove_user.py person@mariarochagroup.com
This removes their entry from vault.json. To also make sure an old copy of
vault.json can never open future data, rotate the keys with tools/rotate_keys.py.
"""
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
from scc_crypto import load_vault, save_json, email_id
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
vp = os.path.join(root, "vault.json"); vault = load_vault(vp)
h = email_id(sys.argv[1]); n = len(vault["users"])
vault["users"] = [u for u in vault["users"] if u["h"] != h]
save_json(vault, vp); print("Removed" if len(vault["users"]) < n else "No such user")
