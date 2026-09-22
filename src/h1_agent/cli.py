from __future__ import annotations

import argparse
import json
from .config import Settings
from .hackerone import HackerOneClient


def main() -> None:
    parser = argparse.ArgumentParser(prog="h1-agent")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("programs", help="List HackerOne programs available to the account")
    args = parser.parse_args()
    settings = Settings()
    if args.command == "programs":
        settings.require_hackerone_credentials()
        client = HackerOneClient(settings.hackerone_username, settings.hackerone_api_token, settings.hackerone_base_url)
        try:
            print(json.dumps(client.programs(), indent=2))
        finally:
            client.close()

if __name__ == "__main__":
    main()
