## CAPE 샌드박스 구축을 통한 악성코드 자동 탐지 및 분석

> **CAPE_Origin** : 원본 CAPE 코드 ( https://github.com/kevoreilly/CAPEv2 )


### CAPE 커스텀 구조 추가
각각의 실행 방식은 내부 README 문서 참고

* YHH_Noise_Filter : 노이즈 필터링 (윈도우 OS의 정상 행위 필터링)
* KSY_YARA_Rules : 커스텀 YARA (랜섬웨어)
* SME_YARA : 커스텀 YARA (레드라인 스틸러)
* YYB_Signature : 커스텀 Signature (LOLBins, 지속성, 민감정보)
* KJH_Discord_Module : 리포트 및 알림 디스코드 전송
