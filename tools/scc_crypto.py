"""Shared encryption helpers for the Social Command Center site.

How the lock works
- One RSA-OAEP 3072 key pair protects everything.
- The PUBLIC key is stored in vault.json. Anything can be encrypted with it
  (the daily data refresh only needs this), but nothing can be read with it.
- The PRIVATE key is never stored in plain form. For each person who can log in,
  vault.json keeps a copy of the private key encrypted with a key derived from
  that person's password (PBKDF2-SHA256, 600,000 rounds, AES-256-GCM).
- app.enc.json and data.enc.json are each encrypted with a fresh AES-256-GCM key,
  and that key is wrapped with the public key.
So the site, the repo and every file in it are unreadable without a valid
email + password.
"""
import base64, hashlib, json, os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ITER = 600_000
b64 = lambda b: base64.b64encode(b).decode()
ub64 = lambda s: base64.b64decode(s)
OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)

def email_id(email):
    return hashlib.sha256(("scc:" + email.strip().lower()).encode()).hexdigest()

def pw_key(password, salt, iterations=ITER):
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations).derive(password.encode())

def new_keypair():
    k = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    pub = k.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    priv = k.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return pub, priv

def wrap_for_user(priv_der, email, password):
    salt, iv = os.urandom(16), os.urandom(12)
    wk = AESGCM(pw_key(password, salt)).encrypt(iv, priv_der, None)
    return {"h": email_id(email), "s": b64(salt), "iv": b64(iv), "wk": b64(wk)}

def unwrap_user(vault, email, password):
    h = email_id(email)
    for u in vault["users"]:
        if u["h"] == h:
            return AESGCM(pw_key(password, ub64(u["s"]), vault.get("iter", ITER))).decrypt(ub64(u["iv"]), ub64(u["wk"]), None)
    raise SystemExit("No user with that email.")

def seal(obj, pub_der):
    pub = serialization.load_der_public_key(pub_der)
    key, iv = AESGCM.generate_key(256), os.urandom(12)
    ct = AESGCM(key).encrypt(iv, json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode(), None)
    return {"v": 1, "ek": b64(pub.encrypt(key, OAEP)), "iv": b64(iv), "ct": b64(ct)}

def open_box(box, priv_der):
    priv = serialization.load_der_private_key(priv_der, password=None)
    key = priv.decrypt(ub64(box["ek"]), OAEP)
    return json.loads(AESGCM(key).decrypt(ub64(box["iv"]), ub64(box["ct"]), None))

def load_vault(path="vault.json"):
    return json.load(open(path))

def save_json(obj, path):
    with open(path, "w") as f:
        json.dump(obj, f, ensure_ascii=False, separators=(",", ":"))
