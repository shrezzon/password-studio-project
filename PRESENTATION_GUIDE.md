# Presentation and viva guide

This guide helps you explain the project in simple terms. Run the application and practice the demonstration once before presenting. Use only example credentials during the presentation.

## One-minute introduction

“My project is a Password Strength Analyzer and Encrypted Password Vault. The problem is that people often choose predictable passwords or reuse the same password across accounts. They also need a safer place to keep different passwords.

My application has three main functions. It analyzes a password using rules and a list of common passwords. It generates a random password according to the user's chosen length and character types. It also stores account details in a local encrypted vault protected by a master password.

I used Python and Flask for the application and the cryptography library for encryption. The vault uses a key derived from the master password. The master password itself is checked against a separately salted hash. The application temporarily locks after three incorrect login attempts.”

## Demonstration in six steps

1. **Analyze a weak example.** Enter `Rahul1999!`. Explain the year, name, and repetition warnings, the score, and the selected character types. Explain that the random-model time is only an illustration and does not account fully for predictable patterns.
2. **Generate.** Choose 20 characters and the four character types. Generate a password. Explain that the program uses Python's `secrets` module and includes every selected type.
3. **Create the vault.** Create and confirm a *demonstration* master password with at least 12 characters. Do not show or use a real master password. Add a fake account, username and password.
4. **Show the file.** Open `vault_data.json` in a text editor. Point out the salts, master verification hash, and ciphertext. Search for the fake account name or password: they should not appear in plaintext.
5. **Lock and unlock.** Lock the vault and unlock it again with your demo master password. If time permits, lock it, enter an incorrect password three times, and show the 30-second lock. Wait for it to expire before trying the correct password.
6. **Compare.** Open **Crack-time demo**. Explain that the known common password can be tried very early and that a random example has a much larger estimated search space. The assumed speed is 10 billion guesses per second; the actual time depends on the target and attack.

## Likely viva questions

**What is the difference between hashing and encryption?**  
Hashing produces a verification value and is not intended to be reversed. Encryption is reversible with the correct key. The application hashes the master password for verification but encrypts saved credentials because the user needs to read them again.

**What is a salt and why are there two?**  
A salt is a random value used with a password-based function. This project generates one salt for the master-password verifier and a separate salt for the vault encryption key. Salts are stored with the file and do not have to be secret.

**What does PBKDF2 do?**  
PBKDF2 repeatedly applies a keyed hash function to a password and salt to derive bytes. The project uses PBKDF2-HMAC-SHA256 with 600,000 iterations. Its work factor makes each password guess more expensive than a single fast hash.

**How are credentials encrypted?**  
A key is derived from the master password and the vault salt. Fernet encrypts the full credential list using AES-128-CBC and protects it against modification using HMAC-SHA256. A wrong key or a modified encrypted value fails authentication.

**Is a high entropy estimate proof of a strong human password?**  
No. The displayed formula assumes random characters from a pool. Humans use words, years and patterns, which attackers can try much earlier. The score and time are teaching estimates rather than guarantees.

**Does the three-attempt lock stop an attacker who steals the file?**  
No. It slows repeated attempts through the application and survives an ordinary restart. Someone with a copy of the file can attempt offline guesses; the master password's strength and the key derivation cost remain important.

**What are the limitations?**  
The lists and strength rules are simple, the vault has no recovery or master-password change, clipboard contents do not clear automatically, and the application is not independently audited. It is a local college demonstration rather than a production password manager.

**How did you test it?**  
Run `python -m unittest discover -s tests -v` from the project folder using the virtual environment's Python. Tests cover pattern detection, generation, encryption, ciphertext tampering, vault operations, lockout, and form/session checks. A table records 15 synthetic password examples. The report images are rendered from tested server responses; interactive browser controls should also be checked on the presentation computer.
