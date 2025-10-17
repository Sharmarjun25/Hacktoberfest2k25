import argparse
import secrets
import string

AMBIGUOUS = "Il1O0"

def generate_password(length=12, use_upper=True, use_lower=True, use_digits=True, use_symbols=True, avoid_ambiguous=False):
    if length < 1:
        raise ValueError("length must be >= 1")
    pools = []
    if use_lower:
        pools.append(string.ascii_lowercase)
    if use_upper:
        pools.append(string.ascii_uppercase)
    if use_digits:
        pools.append(string.digits)
    if use_symbols:
        # a reasonably safe set of symbols
        pools.append("!@#$%&*+-=?_")
    if not pools:
        raise ValueError("At least one character set must be enabled")
    # create combined pool
    combined = "".join(pools)
    if avoid_ambiguous:
        combined = "".join(ch for ch in combined if ch not in AMBIGUOUS)
        pools = [''.join(ch for ch in p if ch not in AMBIGUOUS) for p in pools]
    # ensure at least one char from each enabled category to improve strength
    password_chars = []
    for pool in pools:
        password_chars.append(secrets.choice(pool))
    # fill the rest
    while len(password_chars) < length:
        password_chars.append(secrets.choice(combined))
    # shuffle securely
    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars[:length])


def main():
    parser = argparse.ArgumentParser(description="Secure password generator")
    parser.add_argument("--length", "-l", type=int, default=12, help="length of each password (default: 12)")
    parser.add_argument("--count", "-n", type=int, default=1, help="how many passwords to generate (default: 1)")
    parser.add_argument("--no-upper", action="store_true", help="disable uppercase letters")
    parser.add_argument("--no-lower", action="store_true", help="disable lowercase letters")
    parser.add_argument("--no-digits", action="store_true", help="disable digits")
    parser.add_argument("--no-symbols", action="store_true", help="disable symbols")
    parser.add_argument("--avoid-ambiguous", action="store_true", help="avoid ambiguous characters like O, 0, l, 1")
    args = parser.parse_args()

    use_upper = not args.no_upper
    use_lower = not args.no_lower
    use_digits = not args.no_digits
    use_symbols = not args.no_symbols

    for _ in range(args.count):
        print(generate_password(length=args.length, use_upper=use_upper, use_lower=use_lower, use_digits=use_digits, use_symbols=use_symbols, avoid_ambiguous=args.avoid_ambiguous))


if __name__ == "__main__":
    main()
