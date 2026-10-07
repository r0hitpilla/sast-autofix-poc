"""Command-line administration. Run on the server, not over the web.

    python -m dashboard.manage create-user "Your Name" --email you@example.com --role admin

The password is read from the terminal, never from the command line, so it
doesn't end up in shell history.
"""

import argparse
import getpass
import sys

from sqlalchemy import func, select

from . import auth
from .db import User, make_sessionmaker


def create_user(name: str, email: str, role: str) -> int:
    email = email.strip().lower()
    name = name.strip()
    if len(name) < 2:
        print("name must be at least 2 characters (it is what you sign in with)", file=sys.stderr)
        return 1
    if role not in auth.ROLES:
        print(f"role must be one of: {', '.join(auth.ROLES)}", file=sys.stderr)
        return 1
    password = getpass.getpass("Password: ")
    if getpass.getpass("Repeat password: ") != password:
        print("passwords do not match", file=sys.stderr)
        return 1
    if len(password) < auth.MIN_PASSWORD_LENGTH:
        print(f"password must be at least {auth.MIN_PASSWORD_LENGTH} characters", file=sys.stderr)
        return 1
    Session = make_sessionmaker()
    with Session.begin() as session:
        if session.scalar(select(User.id).where(func.lower(User.name) == name.lower())):
            print(f"a user named {name!r} already exists", file=sys.stderr)
            return 1
        if session.scalar(select(User.id).where(User.email == email)):
            print(f"{email} already exists", file=sys.stderr)
            return 1
        user = User(email=email, name=name, role=role, password_hash=auth.hash_password(password),
                    active=True, created_at=auth.now())
        session.add(user)
        session.flush()
        auth.record(session, "user_created", target=email, detail={"role": role, "via": "cli"})
    print(f"created {name} <{email}> ({auth.ROLE_LABELS[role]})")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m dashboard.manage")
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create-user", help="add a dashboard user")
    create.add_argument("name", help="the name they sign in with (unique, ignoring case)")
    create.add_argument("--email", required=True)
    create.add_argument("--role", required=True, choices=sorted(auth.ROLES))
    args = parser.parse_args(argv)
    if args.command == "create-user":
        return create_user(args.name, args.email, args.role)
    return 1


if __name__ == "__main__":
    sys.exit(main())
