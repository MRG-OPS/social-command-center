"""Encrypt the dashboard data for the site.

Usage: python3 tools/encrypt_data.py path/to/data.json
Writes data.enc.json next to vault.json. Needs only the public key in vault.json,
so the daily refresh can run it without any password.
Never commit the plain data.json.
"""
import json, sys, os
sys.path.insert(0, os.path.dirname(__file__))
from scc_crypto import load_vault, seal, save_json, ub64
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
vault = load_vault(os.path.join(root, "vault.json"))
data = json.load(open(sys.argv[1]))
save_json(seal(data, ub64(vault["pub"])), os.path.join(root, "data.enc.json"))
print("data.enc.json written")
