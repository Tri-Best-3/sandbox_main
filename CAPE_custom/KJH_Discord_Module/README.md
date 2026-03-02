# CAPEv2 커스텀 디스코드 리포팅 모듈

이 모듈은 CAPEv2의 분석 결과를 사람이 읽기 쉬운 형태(요약본, 상세본)로 가공하여 디스코드 채널로 자동 전송해 주는 스크립트입니다.

## 📂 포함된 파일
1. full_md.py: 분석 데이터를 가공하여 summary.md와 full_details.md 파일을 생성
2. discord.py: 생성된 두 개의 마크다운 파일을 찾아 디스코드 웹훅으로 전송

---

## 🚀 설치 및 적용 가이드

### 1. 모듈 파일 덮어쓰기
압축을 푼 폴더 안에서 터미널을 열고, 아래 명령어를 실행하여 기존 경로에 파일을 덮어씁니다.
$ sudo cp full_md.py discord.py /opt/CAPEv2/modules/reporting/

### 2. 설정 파일 수정 (디스코드 웹훅 주소 입력)
리포팅 설정 파일(reporting.conf)을 열어 모듈을 켜고 웹훅 주소를 입력합니다.
$ sudo nano /opt/CAPEv2/conf/reporting.conf

파일 안에서 [full_md]와 [discord] 섹션을 찾아 아래와 같이 수정하세요.
[full_md]
enabled = yes

[discord]
enabled = yes
url = https://discord.com/api/webhooks/여기에_본인_웹훅_주소_입력

### 3. 소유권 복구 및 서비스 재시작 (★매우 중요)
파일을 덮어쓴 후에는 반드시 소유권을 cape로 변경하고 서비스를 재시작해야 합니다.
$ sudo chown -R cape:cape /opt/CAPEv2/
$ sudo systemctl restart cape-processor

### 4. 수동 테스트 방법
기존에 분석이 끝난 태스크 번호(예: 57번)가 있다면 아래 명령어로 테스트해 볼 수 있습니다.
$ cd /opt/CAPEv2
$ poetry run python3 utils/process.py 57 -r
