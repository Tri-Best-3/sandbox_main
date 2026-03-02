import re
from lib.cuckoo.common.abstracts import Signature


class YBLolbinDownloadExec(Signature):
    name = "yb_lolbin_download_exec"
    description = "[YB] LOLBin-driven download/exec chain (powershell/certutil/bitsadmin/mshta/rundll32) with URL/encoded patterns"
    severity = 3
    confidence = 75
    weight = 2
    categories = ["execution", "command-and-control"]
    authors = ["Yeongbin Yun"]
    minimum = "1.0"
    evented = False
    enabled = True

    LOLBIN_RE = re.compile(
        r"\b(powershell(\.exe)?|cmd(\.exe)?|bitsadmin(\.exe)?|certutil(\.exe)?|mshta(\.exe)?|rundll32(\.exe)?|regsvr32(\.exe)?|wscript(\.exe)?|cscript(\.exe)?)\b",
        re.I,
    )

    # “의미 있는” 다운로드/실행 힌트들 (오탐 줄이는 핵심)
    HIGH_SIGNAL_RE = re.compile(
        r"("
        r"https?://|hxxp|"
        r"invoke-webrequest|iwr|wget|curl|downloadstring|new-object\s+net\.webclient|start-bitstransfer|"
        r"-enc\b|-encodedcommand\b|frombase64string|"
        r"certutil\s+-urlcache\s+-split\s+-f|"
        r"bitsadmin\s+/transfer|"
        r"\|\s*iex\b|"
        r")",
        re.I,
    )

    # 흔히 페이로드가 떨어지는 위치
    SUSP_PATH_RE = re.compile(
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
        # 1) 커맨드라인에서 LOLBin + high-signal 패턴 찾기
        cmd_hits = []
        for src, cmd in self._iter_summary_list("executed_commands", "command_line"):
            if self.LOLBIN_RE.search(cmd) and self.HIGH_SIGNAL_RE.search(cmd):
                cmd_hits.append({"source": src, "command": cmd})

        if not cmd_hits:
            return False

        # 2) 파일 생성/쓰기 흔적이 suspicious path 쪽에 있는지(있으면 신뢰도 상승)
        file_hits = []
        for src, path in self._iter_summary_list("file_created", "file_written", "file_opened", "files"):
            if self.SUSP_PATH_RE.search(path):
                # exe/dll/ps1/js/vbs 같은 실행/스크립트 류는 가산점
                if re.search(r"\.(exe|dll|ps1|js|vbs|bat|cmd|scr)$", path, re.I):
                    file_hits.append({"source": src, "path": path})
                # 확장자 없어도 suspicious path면 약하게 기록
                elif len(file_hits) < 3:
                    file_hits.append({"source": src, "path": path})

        # 3) 조합 조건 (오탐 줄이기)
        # - LOLBin high-signal 1개 이상이면 기본 매치
        # - + suspicious path 파일 흔적이 있으면 더 “다운로드/드롭 체인” 느낌이 강함
        for h in cmd_hits[:5]:
            self.add_match(None, "lolbin_command", h)
        for h in file_hits[:5]:
            self.add_match(None, "suspicious_file_activity", h)

        # confidence 조정(선택적)
        if file_hits:
            self.confidence = 85

        return True
