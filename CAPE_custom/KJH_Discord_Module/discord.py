import requests
import json
import os
from lib.cuckoo.common.abstracts import Report

class Discord(Report):
    order = 100
    options = {"enabled": "yes", "url": ""}

    def run(self, results):
        url = self.options.get("url")
        if not url: return
        try:
            tid = results.get("info", {}).get("id")
            score = results.get("malscore", 0)
            base_path = os.path.join("/opt/CAPEv2/storage/analyses", str(tid), "reports")
            
            files = []
            if os.path.exists(os.path.join(base_path, "summary.md")):
                files.append(("file1", ("Summary_Report.md", open(os.path.join(base_path, "summary.md"), "rb"))))
            if os.path.exists(os.path.join(base_path, "full_details.md")):
                files.append(("file2", ("Full_Analysis.md", open(os.path.join(base_path, "full_details.md"), "rb"))))
            
            # 파란색 텍스트(코드 블록)를 유발하는 백틱( ` ) 등을 제거한 설명문
            payload = {
                "embeds": [{
                    "title": f"🔔 분석 완료 알림 (Task #{tid})",
                    "description": "요약본과 상세 분석 파일을 첨부했습니다. 아래 첨부파일을 확인해주세요.",
                    "color": 15158332 if score >= 6.0 else 65280,
                    "fields": [{"name": "최종 위험 점수", "value": f"**{score}/10.0**"}]
                }]
            }

            if files:
                requests.post(url, data={"payload_json": json.dumps(payload)}, files=files)
                for _, (_, f) in files: f.close()
            else:
                requests.post(url, json=payload)
        except Exception: pass
