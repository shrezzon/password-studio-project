"""Password analysis, generation, and vault cryptography.

This is an educational password manager, intended for local demonstrations.
The functions here do not send passwords to any online service.
"""
import base64
import hashlib
import hmac
import json
import math
import re
import secrets
import string
from pathlib import Path

from cryptography.fernet import Fernet

DATA_DIR = Path(__file__).resolve().parent / "data"
COMMON_PASSWORDS = [line.strip().lower() for line in
                    (DATA_DIR / "common_passwords.txt").read_text(encoding="utf-8").splitlines()
                    if line.strip()]
COMMON_RANK = {password: position for position, password in enumerate(COMMON_PASSWORDS, 1)}
ITERATIONS = 600_000
GUESS_RATE = 10_000_000_000  # illustrative guesses per second; not a measured rate

DICTIONARY_WORDS = (
    "password", "welcome", "football", "cricket", "dragon", "monkey", "sunshine",
    "princess", "computer", "school", "college", "india", "iloveyou", "love",
    "summer", "winter", "secret", "admin", "master", "freedom", "shadow",
    "friend", "family", "flower", "music", "apple", "orange", "banana", "hello",
    "starwars", "superman", "pokemon", "batman", "qwerty", "letmein", "login",
    "correct", "horse", "battery", "staple", "test", "security", "beautiful",
    "mumbai", "delhi", "lucknow", "rainbow", "mountain", "internet", "coffee",
)
COMMON_NAMES = (
    "rahul", "rohit", "amit", "akash", "aditya", "arjun", "anand", "anil",
    "priya", "pooja", "neha", "anjali", "shreya", "shreyansh", "ravi", "rajiv",
    "michael", "jennifer", "john", "james", "sarah", "daniel", "andrew", "jessica",
)
KEYBOARD_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", "abcdefghijklmnopqrstuvwxyz")
CHARACTER_GROUPS = {
    "lowercase": string.ascii_lowercase,
    "uppercase": string.ascii_uppercase,
    "digits": string.digits,
    "symbols": "!@#$%^&*()-_=+[]{}:,.?",
}


def _duration(seconds):
    if seconds < 1:
        return "Less than 1 second"
    units = ((31_557_600, "year"), (86_400, "day"), (3_600, "hour"), (60, "minute"))
    if seconds >= 31_557_600 * 1_000_000_000:
        return "Over 1 billion years"
    for size, name in units:
        if seconds >= size:
            amount = seconds / size
            return f"{amount:,.1f} {name}{'' if abs(amount - 1) < .05 else 's'}"
    return f"{seconds:.1f} seconds"


def analyze_password(password):
    """Return a transparent classroom score and a random-character estimate.

    The entropy formula assumes independent, uniformly random ASCII characters.
    Human-selected passwords generally contain patterns and can be guessed much
    faster. For non-ASCII characters, an ASCII pool is not a meaningful model.
    """
    if not password:
        raise ValueError("Enter a password to analyze.")
    if len(password) > 200:
        raise ValueError("Use at most 200 characters for this demo.")
    lower = password.lower()
    groups = {
        "lowercase": any(c in string.ascii_lowercase for c in password),
        "uppercase": any(c in string.ascii_uppercase for c in password),
        "digits": any(c in string.digits for c in password),
        "symbols": any(c in string.punctuation or c == " " for c in password),
    }
    pools = {"lowercase": 26, "uppercase": 26, "digits": 10, "symbols": 33}
    pool = sum(pools[group] for group, present in groups.items() if present)
    non_ascii = any(not c.isascii() for c in password)
    unsupported = any(c.isascii() and not (c.isalnum() or c in string.punctuation or c == " ") for c in password)
    entropy = round(len(password) * math.log2(pool), 1) if pool and not (non_ascii or unsupported) else None
    score = min(len(password), 20) * 3 + sum(groups.values()) * 10
    warnings = []
    rank = COMMON_RANK.get(lower)
    if rank is not None:
        warnings.append("This exact password is on the offline common-password list.")
        score = min(score, 10)
    if any(piece in lower or piece[::-1] in lower
           for row in KEYBOARD_ROWS for piece in (row[i:i + 4] for i in range(len(row) - 3))):
        warnings.append("Contains a keyboard or alphabetical/number sequence.")
        score = min(score, 30)
    if re.search(r"(.)\1{2,}", lower) or re.search(r"(.{2,5})\1", lower):
        warnings.append("Contains repeated characters or repeated groups.")
        score = min(score, 25)
    if any(word in lower for word in DICTIONARY_WORDS):
        warnings.append("Contains a word from the small built-in dictionary.")
        score = min(score, 35)
    if re.search(r"(?:19|20)\d{2}", password):
        warnings.append("Contains a year between 1900 and 2099.")
        score = min(score, 60)
    if any(name in lower for name in COMMON_NAMES):
        warnings.append("Contains a name from the small built-in name list.")
        score = min(score, 35)
    if non_ascii or unsupported:
        warnings.append("Random-character estimate is unavailable for this character set.")
    if not warnings:
        warnings.append("No listed patterns found; this does not guarantee safety.")
    score = max(0, min(score, 100))
    label = ("Very weak" if score < 20 else "Weak" if score < 40 else
             "Fair" if score < 60 else "Strong" if score < 80 else "Very strong")
    if rank is not None:
        crack_time = _duration(rank / GUESS_RATE)
        model = f"List guess at rank {rank} at {GUESS_RATE:,} guesses/second"
    elif entropy is not None:
        log_seconds = entropy - 1 - math.log2(GUESS_RATE)  # average of a full random search
        crack_time = "Over 1 billion years" if log_seconds > 85 else _duration(2 ** log_seconds)
        model = f"Average random search at {GUESS_RATE:,} guesses/second"
    else:
        crack_time = "Not estimated"
        model = "Character set is outside the model"
    return {"length": len(password), "groups": groups, "score": score, "label": label,
            "entropy": entropy, "warnings": warnings, "crack_time": crack_time, "model": model,
            "common_rank": rank}


def generate_password(length, selected_groups):
    if not 8 <= length <= 64:
        raise ValueError("Choose a length between 8 and 64.")
    if not selected_groups or any(name not in CHARACTER_GROUPS for name in selected_groups):
        raise ValueError("Select at least one character type.")
    # Draw uniformly from the combined pool until each requested type appears.
    # This produces a uniformly chosen string among the valid combinations.
    groups = [CHARACTER_GROUPS[name] for name in selected_groups]
    pool = "".join(groups)
    while True:
        candidate = "".join(secrets.choice(pool) for _ in range(length))
        if all(any(char in group for char in candidate) for group in groups):
            return candidate


def _derive(master_password, salt):
    return hashlib.pbkdf2_hmac("sha256", master_password.encode("utf-8"), salt, ITERATIONS, dklen=32)


def new_vault(master_password):
    auth_salt = secrets.token_bytes(16)
    vault_salt = secrets.token_bytes(16)
    master_hash = _derive(master_password, auth_salt)
    key = base64.urlsafe_b64encode(_derive(master_password, vault_salt))
    data = {"version": 1, "iterations": ITERATIONS,
            "auth_salt": base64.b64encode(auth_salt).decode("ascii"),
            "vault_salt": base64.b64encode(vault_salt).decode("ascii"),
            "master_hash": base64.b64encode(master_hash).decode("ascii"),
            "ciphertext": encrypt_entries([], key), "failed_attempts": 0, "locked_until": 0}
    return data, key


def verify_master(master_password, data):
    auth_salt = base64.b64decode(data["auth_salt"])
    expected = base64.b64decode(data["master_hash"])
    return hmac.compare_digest(_derive(master_password, auth_salt), expected)


def vault_key(master_password, data):
    salt = base64.b64decode(data["vault_salt"])
    return base64.urlsafe_b64encode(_derive(master_password, salt))


def encrypt_entries(entries, key):
    return Fernet(key).encrypt(json.dumps(entries, ensure_ascii=False).encode("utf-8")).decode("ascii")


def decrypt_entries(ciphertext, key):
    return json.loads(Fernet(key).decrypt(ciphertext.encode("ascii")).decode("utf-8"))
