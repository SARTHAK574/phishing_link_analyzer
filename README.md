# phishing_link_analyzer
# 🔗 Phishing Link Analyzer Tool (Python CLI)

A Python-based command-line tool that detects **potential phishing links** using pattern-based heuristics and optional **VirusTotal integration**. It can also generate a **PDF report** of the findings.

---

## 🧠 Features

- ✅ Heuristic URL analysis (IP-based, suspicious keywords, hex encoding, etc.)
- ✅ Flags dangerous patterns (e.g., `@` in URL, excessive subdomains)
- ✅ Danger score (0–100) with classification: Safe, Suspicious, High Risk
- ✅ Optional VirusTotal API integration for domain reputation
- ✅ Optional PDF export report
- ✅ CLI-based and beginner-friendly

---

## 🚀 Installation

### 🔧 Prerequisites

- Python 3.x
- Install dependencies:

```bash
pip install validators requests
pip install fpdf  # optional for PDF export
