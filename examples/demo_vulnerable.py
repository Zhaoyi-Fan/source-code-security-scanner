"""Intentionally insecure synthetic snippets for the README demo.

These values are fictional. Do not copy these patterns into production code.
"""

import hashlib
import pickle
import subprocess


password = "SYNTH-demo-password-A1b2C3d4"
user_id = input("User ID: ")
query = "SELECT * FROM users WHERE id=" + user_id
subprocess.run("account-tool --id " + user_id, shell=True)
profile = pickle.loads(input("Serialized profile: ").encode())
digest = hashlib.md5(b"synthetic-demo").hexdigest()
