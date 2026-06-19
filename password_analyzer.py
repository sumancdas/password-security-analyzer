from __future__ import annotations

import argparse
import math
import re
from dataclasses import dataclass


COMMON_PASSWORDS = {
    "password",
    "password1",
    "qwerty",
    "qwerty123",
    "admin",
    "letmein",
    "welcome",
    "iloveyou",
    "monkey",
    "dragon",
    "football",
    "abc123",
    "123456",
    "123456789",
    "111111",
}

KEYBOARD_PATTERNS = ("qwerty", "asdf", "zxcv", "12345", "98765", "qaz", "1q2w")
COMMON_TOKENS = ("password", "admin", "welcome", "letmein", "qwerty")


@dataclass
class PasswordReport:
    score: int
    rating: str
    entropy_bits: float
    findings: list[str]
    recommendations: list[str]


def charset_size(password: str) -> int:
    size = 0
    if re.search(r"[a-z]", password):
        size += 26
    if re.search(r"[A-Z]", password):
        size += 26
    if re.search(r"\d", password):
        size += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        size += 33
    return max(size, 1)


def estimate_entropy(password: str) -> float:
    return len(password) * math.log2(charset_size(password))


def contains_sequence(password: str) -> bool:
    lowered = password.lower()
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    numbers = "0123456789"
    for index in range(len(alphabet) - 3):
        if alphabet[index : index + 4] in lowered:
            return True
    for index in range(len(numbers) - 3):
        if numbers[index : index + 4] in lowered:
            return True
    return False


def analyze_password(password: str, context_terms: list[str] | None = None) -> PasswordReport:
    findings: list[str] = []
    recommendations: list[str] = []
    lowered = password.lower()
    context_terms = [term.strip().lower() for term in context_terms or [] if term.strip()]
    entropy = estimate_entropy(password)
    score = 100

    if len(password) < 12:
        score -= 25
        findings.append("Password is shorter than the recommended 12 characters.")
        recommendations.append("Use at least 14 characters for important accounts.")
    if lowered in COMMON_PASSWORDS or any(token in lowered for token in COMMON_TOKENS):
        score -= 45
        findings.append("Password appears in or closely resembles a common password pattern.")
        recommendations.append("Avoid common or previously leaked passwords.")
    if any(pattern in lowered for pattern in KEYBOARD_PATTERNS):
        score -= 20
        findings.append("Password contains a keyboard pattern.")
        recommendations.append("Avoid keyboard walks such as qwerty or 12345.")
    if contains_sequence(password):
        score -= 15
        findings.append("Password contains an alphabetical or numeric sequence.")
        recommendations.append("Use unrelated words or a password manager generated value.")
    if re.search(r"(.)\1{2,}", password):
        score -= 15
        findings.append("Password contains repeated characters.")
        recommendations.append("Avoid repeated characters such as aaa or 111.")
    if not re.search(r"[a-z]", password) or not re.search(r"[A-Z]", password) or not re.search(r"\d", password):
        score -= 15
        findings.append("Password lacks character diversity.")
        recommendations.append("Mix lowercase, uppercase, numbers, and symbols where allowed.")
    if entropy < 50:
        score -= 20
        findings.append("Estimated entropy is low.")
        recommendations.append("Prefer a longer passphrase with unrelated words.")
    if any(term and term in lowered for term in context_terms):
        score -= 25
        findings.append("Password contains personal or contextual information.")
        recommendations.append("Do not use names, cities, dates, schools, or employer names.")

    score = max(0, min(100, score))
    if score >= 85:
        rating = "strong"
    elif score >= 65:
        rating = "moderate"
    elif score >= 40:
        rating = "weak"
    else:
        rating = "critical"

    if not findings:
        findings.append("No major issues detected by local checks.")
    if not recommendations:
        recommendations.append("Store this password in a reputable password manager.")

    return PasswordReport(score, rating, round(entropy, 2), findings, sorted(set(recommendations)))


def format_report(password: str, report: PasswordReport) -> str:
    masked = password[:2] + "*" * max(0, len(password) - 4) + password[-2:] if len(password) > 4 else "*" * len(password)
    lines = [
        "Password Security Report",
        "=" * 28,
        f"Password: {masked}",
        f"Rating: {report.rating}",
        f"Score: {report.score}/100",
        f"Estimated entropy: {report.entropy_bits} bits",
        "",
        "Findings",
    ]
    lines.extend(f"- {finding}" for finding in report.findings)
    lines.append("")
    lines.append("Recommendations")
    lines.extend(f"- {recommendation}" for recommendation in report.recommendations)
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Ethical password risk analyzer.")
    parser.add_argument("--password", help="Password to analyze.")
    parser.add_argument("--context", default="", help="Comma-separated personal terms to flag.")
    parser.add_argument("--demo", action="store_true")
    args = parser.parse_args()

    examples = ["password123", "Karachi1999!", "CorrectHorseBatteryStaple2026!"]
    passwords = examples if args.demo else [args.password]
    if not passwords[0]:
        parser.error("Provide --password or use --demo.")

    context = args.context.split(",") if args.context else []
    for password in passwords:
        print(format_report(password, analyze_password(password, context)))
        print()


if __name__ == "__main__":
    main()
