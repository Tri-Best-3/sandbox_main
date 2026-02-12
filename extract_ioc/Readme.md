## .py 파일 저장 경로
/opt/CAPEv2/tools/extract_ioc.py
* cape 권한 이슈로 CAPE 폴더 내부에 저장

## 실행 방법
sudo -u cape python3 /opt/CAPEv2/tools/extract_ioc.py /opt/CAPEv2/storage/analyses/<ID>/reports/report.json
 * 원하는 분석한 ID 번호 값 입력

## 저장 경로
* out_dir : (home/<사용자>/Desktop/CAPEv2/summary)
* 바탕화면에 CAPEv2 폴더를 두고 사용중이라 고정경로 상태..
* main 함수에서 out_dir 값만 필요한 위치로 변경

## 권한 문제
cape 를 사용해서 결과물을 생성하기 때문에 cape 사용자 경로가 아닐 경우 수정 불가능할 수 있음
sudo chown <user>:<user> /<out_dir>/ioc_summary_<ID>.*
