import os
from lib.cuckoo.common.abstracts import Report

class FullMD(Report):
    order = 10
    options = {"enabled": "yes"}

    def run(self, results):
        summary_path = os.path.join(self.reports_path, "summary.md")
        full_path = os.path.join(self.reports_path, "full_details.md")

        try:
            info = results.get("info", {})
            target = results.get("target", {})
            score = results.get("malscore", 0)
            sigs = results.get("signatures", [])
            behavior = results.get("behavior", {})
            net = results.get("network", {})

            # --- [Part 1] 요약본 (Summary) ---
            s_lines = [f"# 분석 요약 보고서 #{info.get('id')}", f"위험 점수: {score}/10.0\n"]
            s_lines.append("\n[주요 탐지 항목]")
            for s in sigs[:15]:
                sev = s.get("severity", 1)
                level = "주의" if sev == 1 else "경고" if sev == 2 else "심각"
                s_lines.append(f"- [{level}] {s.get('name')}")
            
            with open(summary_path, "w", encoding="utf-8") as f:
                f.write("\n".join(s_lines))

            # --- [Part 2] 상세본 (Full) ---
            f_lines = [f"# 상세 분석 보고서 #{info.get('id')}", "=============================="]
            
            if "processtree" in behavior:
                f_lines.append("\n[프로세스 실행 계층]")
                for p in behavior["processtree"]:
                    f_lines.append(f"- 실행 프로세스: {p.get('name')} (PID: {p.get('pid')})")
                    if p.get("children"):
                        for c in p.get("children"):
                            f_lines.append(f"  └─ 자식 프로세스: {c.get('name')} (PID: {c.get('pid')})")

            f_lines.append("\n[네트워크 연결 상세]")
            if "domains" in net and net["domains"]:
                f_lines.append("- 접속 도메인 목록:")
                for d in net["domains"]:
                    f_lines.append(f"  > {d.get('domain')} (IP: {d.get('ip')})")

            f_lines.append("\n[탐지된 상세 행위 분석]")
            for s in sigs:
                sev = s.get("severity", 1)
                level = "낮음" if sev == 1 else "중간" if sev == 2 else "높음"
                f_lines.append(f"- 행위명: {s.get('name')}")
                f_lines.append(f"  위험도: {level}")
                f_lines.append(f"  상세설명: {s.get('description')}")
                f_lines.append("")

            summary = behavior.get("summary", {})
            if "file_created" in summary:
                f_lines.append("[생성된 파일 목록 (Top 20)]")
                for f_path in summary["file_created"][:20]:
                    f_lines.append(f"- {f_path}")

            with open(full_path, "w", encoding="utf-8") as f:
                f.write("\n".join(f_lines))

        except Exception: pass
