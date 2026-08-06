import argparse
import getpass

from .auth import hash_password


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate an AWE admin password hash")
    parser.add_argument("password", nargs="?", help="Omit to enter it without terminal echo")
    args = parser.parse_args()
    password = args.password or getpass.getpass("Admin password: ")
    if not password:
        raise SystemExit("Password cannot be empty")
    print(hash_password(password))


if __name__ == "__main__":
    main()
