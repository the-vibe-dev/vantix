from __future__ import annotations

import argparse
import sys
from typing import Iterable

from secops.db import SessionLocal
from secops.models import User
from secops.services.auth_service import hash_password, revoke_all_for_user


VALID_ROLES = {"viewer", "operator", "admin"}


def _print_rows(rows: Iterable[User]) -> None:
    print("username\trole\tdisabled\tlast_login_at")
    for row in rows:
        last_login = row.last_login_at.isoformat() if row.last_login_at else ""
        print(f"{row.username}\t{row.role}\t{int(bool(row.disabled))}\t{last_login}")


def cmd_list(_: argparse.Namespace) -> int:
    with SessionLocal() as db:
        rows = db.query(User).order_by(User.username.asc()).all()
        _print_rows(rows)
    return 0


def cmd_upsert(args: argparse.Namespace) -> int:
    if args.role not in VALID_ROLES:
        print(f"invalid role: {args.role}", file=sys.stderr)
        return 2
    with SessionLocal() as db:
        user = db.query(User).filter(User.username == args.username).first()
        created = False
        if user is None:
            user = User(username=args.username, role=args.role, disabled=False, password_hash=hash_password(args.password))
            db.add(user)
            created = True
        else:
            user.role = args.role
            user.disabled = False
            if args.password:
                user.password_hash = hash_password(args.password)
                revoke_all_for_user(db, user.id)
        db.commit()
        print(f"{'created' if created else 'updated'} user={user.username} role={user.role}")
    return 0


def cmd_set_password(args: argparse.Namespace) -> int:
    with SessionLocal() as db:
        user = db.query(User).filter(User.username == args.username).first()
        if user is None:
            print(f"user not found: {args.username}", file=sys.stderr)
            return 1
        user.password_hash = hash_password(args.password)
        revoked = revoke_all_for_user(db, user.id)
        db.commit()
        print(f"password updated user={user.username} sessions_revoked={revoked}")
    return 0


def cmd_set_disabled(args: argparse.Namespace, *, disabled: bool) -> int:
    with SessionLocal() as db:
        user = db.query(User).filter(User.username == args.username).first()
        if user is None:
            print(f"user not found: {args.username}", file=sys.stderr)
            return 1
        user.disabled = disabled
        revoked = revoke_all_for_user(db, user.id) if disabled else 0
        db.commit()
        print(f"{'disabled' if disabled else 'enabled'} user={user.username} sessions_revoked={revoked}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Vantix local user administration")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_list = sub.add_parser("list", help="list users")
    p_list.set_defaults(func=cmd_list)

    p_upsert = sub.add_parser("upsert", help="create user or update role/password")
    p_upsert.add_argument("--username", required=True)
    p_upsert.add_argument("--password", required=True)
    p_upsert.add_argument("--role", default="operator")
    p_upsert.set_defaults(func=cmd_upsert)

    p_pw = sub.add_parser("set-password", help="set password for existing user")
    p_pw.add_argument("--username", required=True)
    p_pw.add_argument("--password", required=True)
    p_pw.set_defaults(func=cmd_set_password)

    p_disable = sub.add_parser("disable", help="disable user")
    p_disable.add_argument("--username", required=True)
    p_disable.set_defaults(func=lambda a: cmd_set_disabled(a, disabled=True))

    p_enable = sub.add_parser("enable", help="enable user")
    p_enable.add_argument("--username", required=True)
    p_enable.set_defaults(func=lambda a: cmd_set_disabled(a, disabled=False))

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())

