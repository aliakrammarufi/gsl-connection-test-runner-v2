"""Offline hidden input. Prints only a digest; never accepts a token."""
import getpass
import hashlib
import re
import sys


def main():
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        print("PRIVATE_TERMINAL_REQUIRED")
        return 1
    raw = getpass.getpass("Privately confirmed negative group ID (hidden): ")
    if not re.fullmatch(r"-[1-9][0-9]{0,15}", raw) or not -(2**52) < int(raw) < 0:
        print("INVALID_INPUT")
        return 1
    print(hashlib.sha256(raw.encode()).hexdigest())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
