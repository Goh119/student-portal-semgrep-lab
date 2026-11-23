"""Create a short readable summary of Lab 5 Semgrep JSON results."""
import json
from collections import Counter
from pathlib import Path

source = Path("semgrep-results.json")
if not source.exists():
    raise SystemExit("Missing semgrep-results.json. Run the Semgrep scan first.")
with source.open(encoding="utf-8") as f:
    report = json.load(f)
findings = report.get("results", [])
severities = Counter(r.get("extra", {}).get("severity", "UNKNOWN") for r in findings)
files = Counter(r.get("path", "UNKNOWN") for r in findings)
rules = Counter(r.get("check_id", "UNKNOWN") for r in findings)

lines = ["Student Portal – Semgrep SAST Report", "=" * 38,
         f"Total findings: {len(findings)}", "", "Findings by severity:"]
lines += [f"- {key}: {count}" for key, count in sorted(severities.items())] or ["- None"]
lines += ["", "Affected files:"]
lines += [f"- {key}: {count}" for key, count in files.most_common()] or ["- None"]
lines += ["", "Most frequent rule IDs:"]
lines += [f"- {key}: {count}" for key, count in rules.most_common(10)] or ["- None"]
lines += ["", "Detailed findings:"]
for i, r in enumerate(findings, 1):
    ex = r.get("extra", {})
    lines.extend([f"{i}. {r.get('check_id', 'Unknown rule')}",
                  f"   Severity: {ex.get('severity', 'UNKNOWN')}",
                  f"   Location: {r.get('path', 'UNKNOWN')}:{r.get('start', {}).get('line', '?')}",
                  f"   Explanation: {ex.get('message', '').replace(chr(10), ' ')}"])
if not findings:
    lines.append("- No matches in this scan. This is not proof that the code is vulnerability-free.")
lines.extend(["", "Remediation focus:",
              "Review each reported rule, confirm whether it is a real vulnerability,",
              "fix confirmed issues, and scan again. Document any false positives."])
output = "\n".join(lines) + "\n"
Path("semgrep-report.txt").write_text(output, encoding="utf-8")
print(output)
print("Saved: semgrep-report.txt")
