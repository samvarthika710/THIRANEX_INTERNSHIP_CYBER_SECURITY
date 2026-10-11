
import argparse
import getpass
import math
import re
import sys


COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "abc123", "password1",
    "12345678", "111111", "123123", "letmein", "welcome", "monkey",
    "football", "iloveyou", "admin", "login", "starwars", "dragon",
    "sunshine", "master", "hello", "freedom", "whatever", "qazwsx",
    "trustno1", "654321", "superman", "1qaz2wsx",
}

SEQUENTIAL_RUNS = [
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
]


def has_sequential_run(password: str, run_length: int = 4) -> bool:
    
    lowered = password.lower()
    for seq in SEQUENTIAL_RUNS:
        for i in range(len(seq) - run_length + 1):
            forward = seq[i:i + run_length]
            backward = forward[::-1]
            if forward in lowered or backward in lowered:
                return True
    return False


def has_repeated_chars(password: str, run_length: int = 4) -> bool:
    
    return bool(re.search(r"(.)\1{" + str(run_length - 1) + ",}", password))


def character_pool_size(password: str) -> int:
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 32  
    return pool


def estimate_entropy_bits(password: str) -> float:
   
    pool = character_pool_size(password)
    if pool == 0 or len(password) == 0:
        return 0.0
    return len(password) * math.log2(pool)


def analyze_password(password: str) -> dict:
    length = len(password)
    checks = {
        "length_ok": length >= 8,
        "length_strong": length >= 12,
        "has_lower": bool(re.search(r"[a-z]", password)),
        "has_upper": bool(re.search(r"[A-Z]", password)),
        "has_digit": bool(re.search(r"[0-9]", password)),
        "has_symbol": bool(re.search(r"[^a-zA-Z0-9]", password)),
        "is_common": password.lower() in COMMON_PASSWORDS,
        "has_sequential": has_sequential_run(password),
        "has_repeated": has_repeated_chars(password),
    }

    entropy = estimate_entropy_bits(password)

   
    score = 0
    feedback = []

    if checks["length_ok"]:
        score += 1
    else:
        feedback.append("Use at least 8 characters (12+ is recommended).")

    if checks["length_strong"]:
        score += 1

    variety_count = sum([
        checks["has_lower"], checks["has_upper"],
        checks["has_digit"], checks["has_symbol"],
    ])
    score += variety_count

    if variety_count < 3:
        missing = []
        if not checks["has_lower"]:
            missing.append("lowercase letters")
        if not checks["has_upper"]:
            missing.append("uppercase letters")
        if not checks["has_digit"]:
            missing.append("numbers")
        if not checks["has_symbol"]:
            missing.append("symbols")
        if missing:
            feedback.append("Add " + ", ".join(missing) + " for more variety.")

    if checks["is_common"]:
        score -= 4
        feedback.append("This is one of the most commonly used passwords — avoid it entirely.")

    if checks["has_sequential"]:
        score -= 1
        feedback.append("Avoid sequential patterns like 'abcd' or '1234'.")

    if checks["has_repeated"]:
        score -= 1
        feedback.append("Avoid repeating the same character many times in a row.")

    if entropy >= 60:
        score += 1
    if entropy < 28:
        feedback.append("Password is very predictable in terms of entropy.")

    score = max(0, min(score, 8)) 

    if score <= 2:
        rating = "Very Weak"
    elif score <= 4:
        rating = "Weak"
    elif score <= 5:
        rating = "Moderate"
    elif score <= 6:
        rating = "Strong"
    else:
        rating = "Very Strong"

    if not feedback:
        feedback.append("Looks good! No major issues detected.")

    return {
        "length": length,
        "entropy_bits": round(entropy, 1),
        "score": score,
        "max_score": 8,
        "rating": rating,
        "checks": checks,
        "feedback": feedback,
    }


def print_report(password: str, result: dict) -> None:
    masked = password[0] + "*" * (len(password) - 2) + password[-1] if len(password) > 2 else "*" * len(password)
    print("\n=== Password Strength Report ===")
    print(f"Password (masked): {masked}")
    print(f"Length: {result['length']}")
    print(f"Estimated entropy: {result['entropy_bits']} bits")
    print(f"Score: {result['score']} / {result['max_score']}")
    print(f"Rating: {result['rating']}")
    print("\nSuggestions:")
    for tip in result["feedback"]:
        print(f"  - {tip}")
    print()


def main():
    parser = argparse.ArgumentParser(description="Analyze the strength of a password.")
    parser.add_argument(
        "--password", "-p",
        help="Password to analyze (if omitted, you'll be prompted securely).",
    )
    args = parser.parse_args()

       if args.password:
        result = analyze_password(args.password)
        print_report(args.password, result)
        return

   
    print("Password Strength Analyzer — type 'q' or press Ctrl+C to quit.\n")
    while True:
        try:
            password = getpass.getpass("Enter a password to analyze (input hidden): ")
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye.")
            break

        if password.lower() in ("q", "quit", "exit"):
            print("Goodbye.")
            break

        if not password:
            print("No password entered. Try again, or type 'q' to quit.\n")
            continue

        result = analyze_password(password)
        print_report(password, result)


if __name__ == "__main__":
    main()
