from __future__ import annotations

import json

from .config import Settings
from .worker import run_cycle


def main() -> None:
    result = run_cycle(Settings())
    print(json.dumps(result, ensure_ascii=False))
    if result.get("status") == "error":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
