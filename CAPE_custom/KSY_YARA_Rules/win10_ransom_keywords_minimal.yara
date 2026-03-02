/*
  최소 랜섬웨어 키워드 룰 (Win10)
  - 3개 키워드 중 2개 이상 매칭으로 오탐 감소
*/
// 룰 이름 정의.
rule Win_Ransomware_Keywords_Minimal {
  // 메타데이터 섹션 시작.
  meta:
    // 작성자 식별.
    author = "team"
    // 탐지 단계 분류.
    stage = "a"
    // 룰 상태.
    status = "stable"
    // 룰 설명.
    description = "minimal ransomware keywords"
    // 작성/갱신 날짜.
    date = "2026-02-25"
  // 문자열 패턴 섹션 시작.
  strings:
    // 랜섬웨어 관련 키워드 1.
    $a = "ransom" nocase
    // 랜섬웨어 관련 키워드 2.
    $b = "decrypt" nocase
    // 랜섬웨어 관련 키워드 3.
    $c = "bitcoin" nocase
    // 확장 키워드(탐지 범위 확장).
    $d = "decryptor" nocase
    $e = "your files" nocase
    $f = "payment" nocase
  // 조건 섹션 시작.
  condition:
    // 6개 중 2개 이상 매칭 시 탐지.
    2 of ($a,$b,$c,$d,$e,$f)
// 룰 블록 종료.
}
