import re
from lib.cuckoo.common.abstracts import Signature


class YBPersistenceInstall(Signature):
    name = "yb_persistence_install"
    description = "[YB] Persistence installation behavior (Run/RunOnce, services, schtasks, startup folder) with suspicious target paths"
    severity = 3
    confidence = 70
    weight = 2
    categories = ["persistence"]
    authors = ["Yeongbin Yun"]
    minimum = "1.0"
    evented = False
    enabled = True

    # Run/RunOnce/Winlogon/Services 계열
    PERSIST_KEY_RE = re.compile(
        r"\\Software\\Microsoft\\Windows\\CurrentVersion\\Run(Once)?\b|"
        r"\\SYSTEM\\CurrentControlSet\\Services\\|"
        r"\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        re.I,
    )

    # schtasks/sc/reg add 같은 지속성 명령 흔적
    PERSIST_CMD_RE = re.compile(
        r"\b(schtasks(\.exe)?\s+/create|sc(\.exe)?\s+create|reg(\.exe)?\s+add)\b",
        re.I,
    )

    # Startup 폴더도 지속성으로 많이 씀
    STARTUP_PATH_RE = re.compile(
        r"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\",
        re.I,
    )

    # 지속성 타겟이 이런 위치면 더 수상함(일반 설치 프로그램이 여길 쓰기도 하지만 악성에서 특히 흔함)
    SUSP_TARGET_RE = re.compile(
        r"\\(temp|appdata\\roaming|appdata\\local|programdata|users\\public|downloads)\\",
        re.I,
    )

    def _iter_summary_list(self, *keys):
        behavior = self.results.get("behavior", {}) or {}
        summary = behavior.get("summary", {}) or {}
        for k in keys:
            for v in summary.get(k, []) or []:
                if isinstance(v, str) and v.strip():
                    yield k, v.strip()

    def run(self):
        reg_hits = []
        cmd_hits = []
        startup_hits = []
        target_suspicious = False

        # 1) registry persistence 흔적
        for src, rk in self._iter_summary_list("regkey_written", "regkey_opened", "regkey_read", "regkey_deleted"):
            if self.PERSIST_KEY_RE.search(rk):
                reg_hits.append({"source": src, "regkey": rk})

        # 2) persistence 명령 실행 흔적
        for src, cmd in self._iter_summary_list("executed_commands", "command_line"):
            if self.PERSIST_CMD_RE.search(cmd):
                cmd_hits.append({"source": src, "command": cmd})
                if self.SUSP_TARGET_RE.search(cmd):
                    target_suspicious = True

        # 3) Startup 폴더 파일 생성/쓰기 흔적
        for src, path in self._iter_summary_list("file_created", "file_written", "files"):
            if self.STARTUP_PATH_RE.search(path):
                startup_hits.append({"source": src, "path": path})
            if self.SUSP_TARGET_RE.search(path) and re.search(r"\.(exe|dll|lnk|vbs|js|bat|cmd|ps1)$", path, re.I):
                target_suspicious = True

        # 조합 조건(오탐 줄이기)
        # - registry persistence OR (schtasks/sc/reg add) OR startup folder 중 하나라도 있으면 기본 매치
        if not (reg_hits or cmd_hits or startup_hits):
            return False

        # 추가로 “수상한 타겟 경로”가 있으면 신뢰도 상승
        if target_suspicious:
            self.confidence = 85

        for h in reg_hits[:5]:
            self.add_match(None, "persistence_registry", h)
        for h in cmd_hits[:5]:
            self.add_match(None, "persistence_command", h)
        for h in startup_hits[:5]:
            self.add_match(None, "startup_folder", h)

        return True
