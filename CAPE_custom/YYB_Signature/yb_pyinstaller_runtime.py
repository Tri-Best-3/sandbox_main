# /opt/CAPEv2/modules/signatures/windows/yb_pyinstaller_runtime_artifacts.py
import re
from lib.cuckoo.common.abstracts import Signature


class YBPyInstallerRuntimeArtifacts(Signature):
    name = "yb_pyinstaller_runtime_artifacts"
    description = "[YB] PyInstaller-like runtime artifacts observed (_MEI temp + base_library.zip / .pyd runtime files)"
    severity = 1
    confidence = 60
    weight = 1
    categories = ["packer", "runtime"]
    authors = ["Yeongbin Yun"]
    minimum = "1.0"
    evented = False
    enabled = True

    def run(self):
        behavior = self.results.get("behavior", {}) or {}
        summary = behavior.get("summary", {}) or {}
        dropped = self.results.get("dropped", []) or []

        mei_hits = []
        pyd_hits = []
        vcruntime_hits = []

        # behavior summary file paths
        for key in ("files", "file_opened", "file_written", "file_created", "file_read"):
            for path in summary.get(key, []) or []:
                if not isinstance(path, str):
                    continue
                if re.search(r"\\Temp\\_MEI\d+\\base_library\.zip$", path, re.I):
                    mei_hits.append({"source": key, "path": path})

        # dropped files
        for d in dropped:
            if not isinstance(d, dict):
                continue
            name = str(d.get("name") or d.get("path") or "")
            if name.lower().endswith(".pyd"):
                pyd_hits.append(name)
            if name.lower() in ("vcruntime140.dll", "vcruntime140_1.dll"):
                vcruntime_hits.append(name)

        # 조건: _MEI/base_library.zip + (pyd 또는 vcruntime)
        if mei_hits and (pyd_hits or vcruntime_hits):
            for h in mei_hits[:5]:
                self.add_match(None, "pyi_temp", h)
            for n in pyd_hits[:10]:
                self.add_match(None, "pyi_pyd", n)
            for n in vcruntime_hits[:5]:
                self.add_match(None, "pyi_runtime", n)
            return True

        return False
