# /opt/CAPEv2/modules/signatures/windows/yb_pyi_sensitive_collection.py
import re
from lib.cuckoo.common.abstracts import Signature


class YBPyInstallerSensitiveCollection(Signature):
    name = "yb_pyi_sensitive_collection"
    description = "[YB] PyInstaller-like runtime artifacts with suspicious browser/wallet data access"
    severity = 3
    confidence = 85
    weight = 2
    categories = ["collection", "credentials"]
    authors = ["Yeongbin Yun"]
    minimum = "1.0"
    evented = False
    enabled = True

    SENSITIVE_PATTERNS = [
        r"\\Google\\Chrome\\User Data\\Default\\Login Data",
        r"\\Google\\Chrome\\User Data\\Default\\Cookies",
        r"\\Google\\Chrome\\User Data\\Default\\Web Data",
        r"\\Google\\Chrome\\User Data\\Local State",
        r"\\Microsoft\\Edge\\User Data\\Local State",
        r"\\BraveSoftware\\Brave-Browser\\User Data\\Local State",
        r"\\Exodus\\",
        r"\\Electrum\\",
        r"wallet\.dat",
    ]

    def run(self):
        behavior = self.results.get("behavior", {}) or {}
        summary = behavior.get("summary", {}) or {}
        dropped = self.results.get("dropped", []) or []

        sensitive_hits = []
        pyi_mei = False
        pyi_runtime_count = 0

        for key in ("files", "file_opened", "file_written", "file_created", "file_read"):
            for path in summary.get(key, []) or []:
                if not isinstance(path, str):
                    continue

                if re.search(r"\\Temp\\_MEI\d+\\base_library\.zip$", path, re.I):
                    pyi_mei = True

                for pat in self.SENSITIVE_PATTERNS:
                    if re.search(pat, path, re.I):
                        sensitive_hits.append({"source": key, "path": path, "pattern": pat})
                        break

        for d in dropped:
            if not isinstance(d, dict):
                continue
            name = str(d.get("name") or d.get("path") or "")
            nl = name.lower()
            if nl.endswith(".pyd") or nl in ("vcruntime140.dll", "vcruntime140_1.dll", "base_library.zip"):
                pyi_runtime_count += 1

        # 조합 조건 (너무 빡세지 않게)
        if len(sensitive_hits) >= 2 and (pyi_mei or pyi_runtime_count >= 3):
            for h in sensitive_hits[:10]:
                self.add_match(None, "sensitive_access", h)
            self.add_match(None, "pyi_signal", {"mei_temp": pyi_mei, "runtime_count": pyi_runtime_count})
            return True

        return False
