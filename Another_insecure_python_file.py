"""
insecure_demo.py

Intentionally insecure examples for Bandit to flag.
Each function is small and easy to understand, with easy "secure" fixes.
"""

import hashlib
import pickle
import random
import subprocess

import requests


# 1) Hard-coded password (Bandit typically flags this)
DB_PASSWORD = "P@ssw0rd123!"


def calculate_from_user_input(expr: str) -> int:
    """
    Insecure: Using eval() on user-controlled input can execute arbitrary code.
    """
    return eval(expr)  # BAD


def list_directory(user_path: str) -> str:
    """
    Insecure: shell=True + string command can lead to shell injection if user_path is untrusted.
    """
    cmd = f"ls {user_path}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)  # BAD
    return result.stdout


def load_session_from_cookie(cookie_bytes: bytes) -> dict:
    """
    Insecure: Unpickling untrusted data can be dangerous.
    """
    return pickle.loads(cookie_bytes)  # BAD


def fetch_profile(url: str) -> str:
    """
    Insecure: Disables TLS certificate verification and omits a timeout.
    """
    resp = requests.get(url, verify=False)  # BAD (no timeout, verify disabled)
    return resp.text


def make_reset_token(username: str) -> str:
    """
    Insecure: Uses weak randomness + weak hash for a "token".
    """
    salt = "".join(random.choice("abcdef0123456789") for _ in range(8))  # BAD
    token = hashlib.md5((username + salt).encode()).hexdigest()  # BAD
    return token
