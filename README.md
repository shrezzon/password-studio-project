# Password Studio

An educational, local web application for checking password strength, generating random passwords, and keeping credentials in an encrypted vault. Built with Python, Flask, HTML/CSS, JavaScript, and the `cryptography` library.

## What the project does

1. **Analyze**: checks length, character types, an offline list of 1,248 distinct common passwords, keyboard/alphabet/number sequences, repeated groups, dictionary words, years, and names.
2. **Generate**: creates an 8–64 character random password using any selected combination of lowercase letters, uppercase letters, digits, and symbols. Every selected type appears at least once.
3. **Vault**: creates, unlocks, locks, adds, reveals, copies, and deletes credentials. Site, username, and password are encrypted together before they are written to disk.
4. **Demonstrate**: compares a common password with a freshly generated example and shows an illustrative guessing-time estimate.
5. **Protect the master login**: stores a salted PBKDF2-HMAC-SHA256 hash, not the master password itself. Three incorrect attempts cause a 30-second lock.

The common-password list is checked locally. It was adapted from the first entries of [Lulu's 10,000 common passwords list](https://mail.lucidar.me/en/security/list-of-10000-most-common-passwords/), with case-insensitive duplicates removed. As a real-world historical list, it contains some offensive words.

## Requirements

- Python 3.10 or newer, including `pip`.
- A modern browser such as Chrome, Edge, or Firefox.
- Internet access **once** to install the Python packages. After installation the app itself works offline.

## Setup on Windows

1. Install Python from [python.org/downloads](https://www.python.org/downloads/) and select **Add Python to PATH** if prompted.
2. Extract the project ZIP. Open the extracted project folder in File Explorer.
3. Click the File Explorer address bar, type `cmd`, and press Enter. A Command Prompt opens in that folder.
4. Run these commands one at a time:

   ```bat
   py --version
   py -m venv .venv
   .venv\Scripts\python.exe -m pip install -r requirements.txt
   .venv\Scripts\python.exe app.py
   ```

5. Open **http://127.0.0.1:5000** in the browser. Keep the terminal open while using the application. To stop it, return to the terminal and press `Ctrl+C`.

If `py` is unavailable but `python --version` works, replace `py` with `python` in the first two commands. If port 5000 is already in use, stop the other local program or change the port in the final line of `app.py`.

## Setup on macOS or Linux

Open a terminal in the project folder and run:

```bash
python3 --version
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python app.py
```

Then visit **http://127.0.0.1:5000**. Press `Ctrl+C` in the terminal to stop the server.

## How to demonstrate the project

1. **Analyze:** enter `Rahul1999!` and click **Analyze password**. Read the score, detected character types, name/year/repetition warnings, and estimate. These are example credentials only.
2. **Generate:** select a length and character types, then click **Generate password**. Each selected character type is represented.
3. **Create the vault:** select **Password vault**, create and confirm a unique master password of at least 12 characters, then add a test account. The master password cannot be recovered if forgotten.
4. **Show encryption:** while the app is open, inspect `vault_data.json` in the project folder. The test site's name, username, and password are not readable in this file. Lock the vault and unlock it again to confirm the entry persists.
5. **Test lockout:** lock the vault, then enter an incorrect master password three times. The app displays a 30-second lock. Wait for it to expire and unlock with the correct master password.
6. **Compare:** open **Crack-time demo**. The weak example is a known common password; the random example is generated for demonstration and changes on refresh.

The file `vault_data.json` is created only after the first vault is set up. It contains encrypted entries, salts, the verification hash, and lockout metadata. To keep a backup, copy this file to a safe location; the same master password is required. Deleting it permanently deletes the vault unless you have a backup. It is not included in the ZIP.

## Testing

Run the automated test suite from the project folder using the same Python installation used for setup:

```bat
.venv\Scripts\python.exe -m unittest discover -s tests -v
```

On macOS/Linux use `.venv/bin/python` instead. The tests use a temporary vault; they do not alter your real `vault_data.json`. They cover common-password and pattern detection, generator settings, ciphertext round trips, tamper and wrong-key detection, vault create/add/lock/unlock/delete, the persisted lockout, form protection, session expiry, and page responses. `tests/sample_password_results.csv` records 15 synthetic analysis examples.

The report's screen captures were rendered from actual application HTML responses generated through Flask's test client. They are not captures of an interactive browser session. The automated suite tests backend routes and rendered responses, but a hands-on browser check on your own computer is still recommended, including Show/Hide and Copy buttons.

## How the security design works

- Two independent random 16-byte salts are created. One is used with PBKDF2-HMAC-SHA256 at 600,000 iterations to verify the master password; the other derives a separate 32-byte Fernet key using the same KDF work factor.
- Fernet provides authenticated encryption: AES-128-CBC for encryption and HMAC-SHA256 for integrity. Tampered ciphertext or the wrong key fails authentication.
- The entire credential list is encrypted before saving. The application uses a random in-memory session key and stores an opaque session token, not the encryption key, in the signed browser cookie. A vault is locked after 15 minutes of inactivity on the next request, when manually locked, or when the application stops.
- Local form submissions require a CSRF token; the app binds to loopback and restricts accepted hostnames. It does not log submitted passwords intentionally. Use only on a trusted computer.
- The time estimate assumes 10 billion guesses per second as an illustrative constant. For a non-listed password, it uses half of the estimated random-character search space; common-list matches use the position in the offline list. The character-pool estimate is an upper approximation and is **not** a reliable estimate for human-chosen passwords. An attacker may prioritize names, patterns, or leaks. The actual rate depends on the target's hashing scheme and attacker.

## Limitations

This is a college demonstration, not an independently audited password manager. It does not provide recovery, synchronization, browser integration, a master-password change feature, TOTP, or automatic clipboard clearing. The dictionary and name lists are small, so they can miss patterns or flag innocent substrings. A single local user is assumed. The application-level lockout survives a normal restart but cannot stop an attacker who copies or changes the vault file, or tries passwords offline. Compromised devices, browser extensions, screen capture, malware, memory inspection, and cloud backups of plaintext are outside the protection offered. Flask's built-in server is for local demonstration only; do not expose it to a network.

## Project files

```text
app.py                         Flask routes, sessions, and local vault file
security.py                    Strength rules, random generator, and encryption
data/common_passwords.txt      Offline common-password list (1,248 entries)
templates/                     Web pages
static/                        Styling and small browser interactions
tests/test_project.py          Automated tests
tests/sample_password_results.csv  15 synthetic password results
screenshots/                   Rendered test-client application screens
requirements.txt               Python package requirements
PRESENTATION_GUIDE.md          Demo script and viva explanations
```

## References

- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [Cryptography: Fernet documentation](https://cryptography.io/en/latest/fernet/)
- [NIST: Strength of Passwords](https://pages.nist.gov/800-63-4/sp800-63b/passwords/)
- [Python `secrets` documentation](https://docs.python.org/3/library/secrets.html)
- [Common password list source](https://mail.lucidar.me/en/security/list-of-10000-most-common-passwords/)
