#!/usr/bin/env python3
"""Compatibility shim for the retired research-header forward proxy.

The old implementation accepted arbitrary Host destinations and forwarded
traffic from a local listener, creating an unauthenticated localhost proxy that
could reach loopback and private network services. TALISMAN now adds the
research identifier directly through its shared HTTP client.
"""
from __future__ import annotations

import argparse
import re
import shlex
import sys


_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Configure the TALISMAN research identifier without starting a proxy."
    )
    parser.add_argument("username", help="Your HackerOne username")
    args = parser.parse_args(argv)

    if not _USERNAME_RE.fullmatch(args.username):
        parser.error("username must contain only letters, digits, dots, underscores or hyphens (max 64 characters)")

    print("The legacy forward proxy has been retired because it exposed an unrestricted local network path.")
    print("TALISMAN's shared HTTP client adds this header directly. Run this in the shell used to start TALISMAN:")
    print(f"export TALISMAN_H1_USERNAME={shlex.quote(args.username)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
