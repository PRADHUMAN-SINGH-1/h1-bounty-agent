from __future__ import annotations

import json
import plistlib
import re
import zipfile
from pathlib import Path

from .models import Evidence


def analyze_mobile_package(path: str) -> tuple[dict, list[Evidence]]:
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(path)

    suffix = file_path.suffix.lower()
    with zipfile.ZipFile(file_path) as archive:
        names = archive.namelist()
        evidence: list[Evidence] = []
        result = {
            "path": str(file_path),
            "format": "apk" if suffix == ".apk" else "ipa" if suffix == ".ipa" else "zip",
            "files": len(names),
            "dex_files": [n for n in names if n.endswith(".dex")],
            "native_libraries": [n for n in names if n.endswith((".so", ".dylib"))],
            "web_assets": [n for n in names if n.endswith((".js", ".json", ".map"))][:100],
            "security_flags": [],
            "url_references": [],
        }

        text_blobs = []
        for name in names[:3000]:
            try:
                raw = archive.read(name)
            except Exception:
                continue
            if len(raw) > 2_000_000:
                continue
            if name.endswith((".xml", ".json", ".plist", ".txt", ".js", ".html", ".map")) or suffix == ".ipa":
                text_blobs.append((name, raw.decode("utf-8", errors="ignore")))

        combined = "\n".join(text for _, text in text_blobs)
        urls = sorted(set(re.findall(r"https?://[A-Za-z0-9._~:/?#\\[\\]@!$&'()*+,;=%-]+", combined)))
        result["url_references"] = urls[:200]

        for flag in ("android:debuggable", "android:usesCleartextTraffic", "networkSecurityConfig", "NSAllowsArbitraryLoads"):
            if flag in combined:
                result["security_flags"].append(flag)

        plist_hits = []
        for name, text in text_blobs:
            if name.endswith(".plist"):
                try:
                    parsed = plistlib.loads(text.encode())
                    plist_hits.append(name)
                    if parsed.get("NSAppTransportSecurity"):
                        result["security_flags"].append("NSAppTransportSecurity_present")
                except Exception:
                    pass

        evidence.extend(
            Evidence("mobile_file_count", str(len(names)), str(file_path)),
            Evidence("mobile_dex_count", str(len(result["dex_files"])), str(file_path)),
            Evidence("mobile_native_count", str(len(result["native_libraries"])), str(file_path)),
            Evidence("mobile_security_flags", json.dumps(result["security_flags"]), str(file_path)),
            Evidence("mobile_url_reference_count", str(len(urls)), str(file_path)),
        )
        return result, evidence
