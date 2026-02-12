#!/usr/bin/env python3
"""
extract_ioc.py

CAPEv2 report.json에서 IOC 후보를 추출하고,
- score (중요도 점수)
- reason (점수 근거 태그)

를 추가한 뒤 score 내림차순으로 정렬하여 JSON/CSV로 저장합니다.

사용법:
  python3 extract_ioc.py /path/to/report.json

※ CAPE report.json은 보통 cape 사용자 권한으로 생성됩니다.
  권한 때문에 읽기 실패하면 아래처럼 실행하세요:
    sudo -u cape python3 extract_ioc.py /opt/CAPEv2/storage/analyses/11/reports/report.json
"""

import csv
import ipaddress
import json
import re
import sys
from pathlib import Path

# -----------------------------
# 1) 룰/정규식 정의
# -----------------------------

# LOLBin/의심 명령에 자주 등장하는 실행 파일들 (단순 키워드 기준)
SUSP_CMD = re.compile(
    r"(powershell|cmd\.exe|wscript|cscript|rundll32|regsvr32|mshta|certutil|bitsadmin|schtasks|wmic)\b",
    re.I,
)

# “지속성(persistence)”에 자주 쓰이는 레지스트리 경로 조각
PERSIST_KEYS = (
    r"\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    r"\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    r"\\SYSTEM\\CurrentControlSet\\Services\\",
    r"\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
)

# 윈도우 정상 경로(읽기/접근 노이즈가 많음). 단, LOLBin 실행 흔적은 별도 가중치로 살립니다.
ALLOW_PATH_PREFIX = (
    r"c:\windows\system32",
    r"c:\program files",
    r"c:\program files (x86)",
)

# 악성에서 자주 쓰는 “사용자 쓰기 가능 경로” 키워드
USER_WRITABLE_HINTS = (
    r"\appdata\roaming",
    r"\appdata\local\temp",
    r"\temp",
    r"\programdata",
    r"\startup",
)

# 사설/로컬 IP 대역은 일반적으로 C2 IOC로서 우선순위가 낮음(실습환경 내부통신 제외 목적)
PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


# -----------------------------
# 2) 유틸 함수들
# -----------------------------

def is_private_ip(s: str) -> bool:
    """문자열이 IP일 때 사설/로컬 IP인지 판단"""
    try:
        ip = ipaddress.ip_address(s.strip())
        return any(ip in n for n in PRIVATE_NETS)
    except ValueError:
        return False


def looks_like_domain(s: str) -> bool:
    """도메인 형태(아주 단순)"""
    return bool(re.fullmatch(r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", s.strip()))


def looks_like_ip(s: str) -> bool:
    """IPv4 형태(아주 단순)"""
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", s.strip()))


def add(iocs, t, v, ctx=""):
    """
    IOC 항목을 중복 없이 추가.
    - iocs["_set"]으로 (type,value,context) 조합 중복 방지
    """
    if not v:
        return
    key = (t, str(v), str(ctx))
    if key not in iocs["_set"]:
        iocs["_set"].add(key)
        iocs["items"].append({"type": t, "value": str(v), "context": str(ctx)})


def walk(obj):
    """
    report.json 내부를 “문자열 기준으로” 전부 훑기 위한 제너레이터.
    - dict/list는 재귀 탐색
    - str이면 yield
    """
    if isinstance(obj, dict):
        for _, v in obj.items():
            yield from walk(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from walk(v)
    elif isinstance(obj, str):
        yield obj


def normalize_file_item(f):
    """
    CAPE 리포트에서 file 리스트 원소는 dict이거나 str일 수 있음.
    dict이면 name/path를 뽑고, category도 있으면 같이 씀.
    """
    if isinstance(f, dict):
        value = f.get("name") or f.get("path") or ""
        category = f.get("category") or "file"
        return value, category
    elif isinstance(f, str):
        return f, "file"
    return "", "file"


# -----------------------------
# 3) 점수화(Severity Scoring)
# -----------------------------

def score_item(t: str, v: str, ctx: str):
    """
    IOC 항목별 점수(score)와 이유(reason tags)를 계산.
    - score는 높을수록 “분석/발표에서 먼저 볼 만한 항목”
    - reason은 점수를 준 근거 태그(여러 개 가능)

    기본 컨셉:
      +50: persistence (Run/Services/Winlogon, schtasks 등)
      +40: LOLBin/의심 명령(특히 인코딩/다운로드)
      +30: 외부 통신(공인 IP/도메인/URL)
      +25: 사용자 쓰기 영역에 생성/접근
      +20: dropped 파일 + 해시 힌트
      +10: mutex
      (필터) 사설 IP는 점수 0 처리 (필요시 바꿔도 됨)
    """
    vlow = (v or "").lower()
    clow = (ctx or "").lower()

    score = 0
    reasons = []

    # (A) Persistence 후보
    if ctx == "persistence_candidate":
        score += 50
        reasons.append("persistence_candidate")

    # regkey나 명령에서 schtasks/services/winlogon/run 흔적이 보이면 persistence로 가중
    if ("schtasks" in vlow) or ("\\services\\" in vlow) or ("\\currentversion\\run" in vlow) or ("\\winlogon" in vlow):
        score += 50
        reasons.append("persistence_pattern")

    # (B) suspicious_command는 기본 고점
    if t == "suspicious_command":
        score += 40
        reasons.append("lolbin_or_susp_cmd")

        # 명령 내부에 “더 위험한” 키워드가 있으면 추가 가중
        # (파워쉘 인코딩/다운로드/실행)
        extra_kw = ("-enc", "encodedcommand", "frombase64string", "downloadstring", "iex", "invoke-webrequest", "curl ", "wget ")
        if any(k in vlow for k in extra_kw):
            score += 20
            reasons.append("encoded_or_download")

    # (C) Network 항목
    if t in ("domain", "url", "ip"):
        # 사설 IP는 보통 IOC로 의미가 약해서 제외(점수 0)
        if t == "ip" and is_private_ip(vlow):
            return 0, ["filtered_private_ip"]

        score += 30
        reasons.append("external_comm_candidate")

        # onion은 환경에 따라 강한 신호라 추가 가중(원하면 삭제 가능)
        if ".onion" in vlow:
            score += 20
            reasons.append("onion_address")

    # (D) File 관련
    if t in ("dropped_file", "file_activity"):
        # 사용자 쓰기 영역이면 가중
        if any(h in vlow for h in USER_WRITABLE_HINTS):
            score += 25
            reasons.append("user_writable_path")

        # 윈도우 정상 경로는 노이즈가 많아 기본 가중 X
        # (단, LOLBin 실행 흔적이 있으면 이미 suspicious_command로 잡히는 편)
        if any(vlow.startswith(p) for p in ALLOW_PATH_PREFIX):
            reasons.append("system_path_noise")

    # (E) dropped_file에서 context에 해시가 있으면(너 스크립트는 context에 sha256/md5를 넣음)
    if t == "dropped_file" and ctx:
        # 매우 단순: 길이가 긴 해시 문자열/“sha256/md5”라는 단어가 있으면 가중
        if ("sha256" in clow) or ("md5" in clow) or (len(ctx) >= 32):
            score += 20
            reasons.append("has_hash_hint")

    # (F) Mutex
    if t == "mutex":
        score += 10
        reasons.append("mutex")

    # 최종
    if score == 0 and not reasons:
        reasons = ["low_signal"]

    return score, reasons


# -----------------------------
# 4) 메인 로직
# -----------------------------

def main(report_path: str):
    """
    report.json을 읽고 IOC 후보를 추출한 뒤,
    score/reason을 붙여 JSON/CSV로 저장합니다.
    """
    p = Path(report_path)
    data = json.loads(p.read_text(encoding="utf-8", errors="ignore"))

    # 중복 제거를 위해 _set을 같이 유지
    iocs = {"items": [], "_set": set()}

    # -------------------------
    # (1) Network IOCs: url/domain/ip
    # - data["network"]는 CAPE 설정/버전에 따라 구조가 다를 수 있으므로 문자열 워커로 best-effort
    # -------------------------
    for s in walk(data.get("network", {})):
        if not isinstance(s, str):
            continue
        ss = s.strip()

        # URL
        if "://" in ss:
            add(iocs, "url", ss, "network")

        # IP
        if looks_like_ip(ss):
            add(iocs, "ip", ss, "network")

        # Domain
        if looks_like_domain(ss):
            add(iocs, "domain", ss.lower(), "network")

    # -------------------------
    # (2) Dropped files
    # - data["dropped"] : CAPE가 떨어뜨린 파일 정보 리스트인 경우가 많음
    # -------------------------
    for f in data.get("dropped", []) or []:
        if isinstance(f, dict):
            name_or_path = f.get("name") or f.get("path") or ""
            # context에는 가능한 해시(sha256 -> md5)를 하나 넣어둠
            hash_ctx = f.get("sha256") or f.get("md5") or ""
            add(iocs, "dropped_file", name_or_path, hash_ctx)
        else:
            # 구조가 다를 때 대비
            add(iocs, "dropped_file", str(f), "")

    # -------------------------
    # (3) File activity
    # - data["target"]["file"] 등이 존재할 수도 있고,
    #   버전에 따라 accessed/modified 등으로 분산되기도 함
    # -------------------------
    for f in data.get("target", {}).get("file", []) or []:
        value, category = normalize_file_item(f)
        add(iocs, "file_activity", value, category)

    # -------------------------
    # (4) Registry keys
    # - behavior 섹션 문자열 전체를 훑어서 HKEY/HKLM/HKCU로 시작하는 문자열을 수집
    # - persistence 후보 key가 포함되면 ctx를 "persistence_candidate"로 지정
    # -------------------------
    for s in walk(data.get("behavior", {})):
        if not isinstance(s, str):
            continue
        if s.startswith(("HKEY_", "HKLM", "HKCU")):
            ctx = "registry"
            for pk in PERSIST_KEYS:
                if pk.lower() in s.lower():
                    ctx = "persistence_candidate"
                    break
            add(iocs, "regkey", s, ctx)

    # -------------------------
    # (5) Suspicious commands
    # - behavior 문자열을 훑으면서 실행/옵션 형태로 보이는 문자열 중
    #   SUSP_CMD(LOLBin) 패턴이 있으면 수집
    # -------------------------
    for s in walk(data.get("behavior", {})):
        if not isinstance(s, str):
            continue
        sl = s.lower()
        # 아주 대충 "명령줄 같아 보이는" 조건
        if (".exe" in sl) or (" /" in s) or (" -" in s):
            if SUSP_CMD.search(s):
                add(iocs, "suspicious_command", s, "behavior")

    # -------------------------
    # (6) Mutexes
    # -------------------------
    for m in data.get("mutexes", []) or []:
        if isinstance(m, dict):
            add(iocs, "mutex", m.get("name", ""), "mutex")
        else:
            add(iocs, "mutex", str(m), "mutex")

    # -------------------------
    # 점수/이유(reason) 추가
    # -------------------------
    for item in iocs["items"]:
        sc, rs = score_item(item["type"], item["value"], item.get("context", ""))
        item["score"] = sc
        item["reason"] = "|".join(rs)  # CSV에 넣기 좋게 '|'로 합침

    # -------------------------
    # 정렬: score 내림차순, 동점이면 type/value로 안정 정렬
    # -------------------------
    iocs["items"].sort(key=lambda x: (x.get("score", 0), x.get("type", ""), x.get("value", "")), reverse=True)

    # 중복 제거용 _set 제거
    del iocs["_set"]

    # 분석 ID 추출: /opt/CAPEv2/storage/analyses/<id>/reports/report.json 형태를 가정
    # p.parent = reports, p.parent.parent = <id>
    analysis_id = p.parent.parent.name

    # 출력 디렉토리(원하는 경로로 고정)
    out_dir = Path("/home/yb/Desktop/CAPEv2/summary")
    # exist_ok=True여도 상위 접근권한이 없으면 터질 수 있음(이미 ACL로 해결한 상태라고 가정)
    out_dir.mkdir(parents=True, exist_ok=True)

    out_json = out_dir / f"ioc_summary_{analysis_id}.json"
    out_csv = out_dir / f"ioc_summary_{analysis_id}.csv"

    # JSON 저장
    out_json.write_text(json.dumps(iocs, indent=2, ensure_ascii=False), encoding="utf-8")

    # CSV 저장
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["type", "value", "context", "score", "reason"])
        w.writeheader()
        w.writerows(iocs["items"])

    print(f"[OK] Wrote: {out_json}")
    print(f"[OK] Wrote: {out_csv}")
    print(f"[INFO] IOC count: {len(iocs['items'])}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: extract_ioc.py /path/to/report.json")
        sys.exit(1)
    main(sys.argv[1])

