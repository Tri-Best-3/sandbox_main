# CAPE Custom Rules Installer

CAPEv2 커스텀 룰(Sigma/YARA/Suricata)을 지정 경로로 복사하고 필요 시
`cape-processor`를 재시작하는 간단 설치/검증 스크립트입니다.

## 포함 파일
- `cape_rules_installer.py`

## 기본 전제
- Sigma: Windows 보안 로그 Event ID 4688 + CommandLine 로깅 활성화 필요
- YARA: CAPE에서 YARA 스캔 경로 활성화 필요
- Suricata: HTTP 트래픽 캡처 활성화 필요(HTTPS는 평문 URI 미노출 가능)

## 사용법
### 1) 경로 검증만
```bash
python3 cape_rules_installer.py --validate-only
```

### 2) 기본 설치
```bash
python3 cape_rules_installer.py
```

### 2-1) 설치 후 대상 파일 존재 확인(로딩 준비 확인)
```bash
python3 cape_rules_installer.py --check-dst
```

### 2-1-1) 대상 파일만 확인(복사 없이)
```bash
python3 cape_rules_installer.py --check-dst-only
```

### 2-2) 런타임 상태 확인(서비스 상태 + 로그 검색)
```bash
python3 cape_rules_installer.py --check-runtime
python3 cape_rules_installer.py --check-runtime --log /opt/CAPEv2/log/cape-processor.log
```
기본 로그 경로가 있을 경우 자동으로 탐색합니다:
`/opt/CAPEv2/log/process.log` → 없으면 `/opt/CAPEv2/log/cuckoo.log`

### 2-2-1) 런타임만 확인(복사 없이)
```bash
python3 cape_rules_installer.py --runtime-only
```

### 3) 설치 후 서비스 재시작
```bash
sudo python3 cape_rules_installer.py --restart
```

### 4) 경로 지정
```bash
python3 cape_rules_installer.py --src /home/my/CAPEv2/custom --dst /opt/CAPEv2/custom
```

### 4-1) 특정 룰만 지정 설치
```bash
python3 cape_rules_installer.py --rules sigma/foo.yml yara/bar.yara
```

### 5) 드라이런
```bash
python3 cape_rules_installer.py --dry-run
```

## 비고
- 기본 소스 경로: `/home/my/CAPEv2/custom`
- 기본 대상 경로: `/opt/CAPEv2/custom`
- 룰 목록은 기본적으로 자동 탐색(`sigma/`, `yara/`, `suricata/`)합니다
