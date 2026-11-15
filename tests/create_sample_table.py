"""Regenerate the 15-example CSV using the current analyzer rules."""
import csv
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import security

SAMPLES = ["123456", "password", "qwerty!", "aaaabbbb", "Rahul1999!", "India2024!",
           "iloveyou", "Password1!", "Aaa111!", "abcdefg", "sunshine99",
           "T9!mP4#vZ2@kL6%r", "C7@wN2!pK8$xF4qZ", "abcdefghijklmnop",
           "F6#uL9!bS2@xW8%eP4^z"]

output = Path(__file__).with_name("sample_password_results.csv")
with output.open("w", newline="", encoding="utf-8") as file:
    writer = csv.writer(file)
    writer.writerow(["number", "sample_password", "score", "label", "findings"])
    for number, password in enumerate(SAMPLES, 1):
        result = security.analyze_password(password)
        writer.writerow([number, password, result["score"], result["label"], "; ".join(result["warnings"])])
print(f"Wrote {len(SAMPLES)} synthetic examples to {output.name}.")
