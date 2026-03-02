# /opt/CAPEv2/modules/signatures/windows/yb_browser_wallet_collection.py
import re
from lib.cuckoo.common.abstracts import Signature


class YBBrowserWalletCollection(Signature):
    name = "yb_browser_wallet_collection"
    description = "[YB] suspicious access to browser credential/session stores or crypto wallet data"
    severity = 3
    confidence = 80
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

        hits = []
        for key in ("files", "file_opened", "file_written", "file_created", "file_read"):
            for path in summary.get(key, []) or []:
                if not isinstance(path, str):
                    continue
                for pat in self.SENSITIVE_PATTERNS:
                    if re.search(pat, path, re.I):
                        hits.append({"source": key, "path": path, "pattern": pat})
                        break

        # 조건: 2개 이상 hit 시 매치 (FP 감소)
        if len(hits) >= 2:
            for h in hits[:10]:
                self.add_match(None, "sensitive_access", h)
            return True

        return False
