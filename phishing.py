import re
import requests
import validators

# Optional: PDF Export
try:
    from fpdf import FPDF
    PDF_ENABLED = True
except ImportError:
    PDF_ENABLED = False

# ------------------ Analysis Engine ------------------ #
def analyze_url(url):
    result = {
        "url": url,
        "is_valid": validators.url(url),
        "features": [],
        "danger_score": 0,
        "verdict": ""
    }

    if not result["is_valid"]:
        result["verdict"] = "❌ Invalid URL format"
        return result

    score = 0
    features = []

    if re.search(r"\d{1,3}(?:\.\d{1,3}){3}", url):
        features.append("🔴 IP address used instead of domain")
        score += 25

    if len(url) > 75:
        features.append("🟠 Very long URL")
        score += 10

    if url.count('-') > 3:
        features.append("🟠 Suspicious use of hyphens")
        score += 5

    if re.search(r"(@|%40)", url):
        features.append("🔴 Use of '@' to mislead actual domain")
        score += 20

    if re.search(r"//.*//", url):
        features.append("🟠 Multiple // in path")
        score += 5

    if re.search(r"[0-9a-fA-F]{4,}", url):
        features.append("🟠 Hex encoding present")
        score += 5

    if re.search(r"(login|verify|update|secure)", url.lower()):
        features.append("🟡 Phishing-related keywords present")
        score += 10

    if url.count('.') > 5:
        features.append("🟠 Too many subdomains")
        score += 10

    result["danger_score"] = min(score, 100)

    if score < 30:
        result["verdict"] = "✅ Likely Safe"
    elif 30 <= score < 60:
        result["verdict"] = "⚠️ Suspicious"
    else:
        result["verdict"] = "🚨 High Risk"

    result["features"] = features
    return result

# ------------------ VirusTotal Check ------------------ #
def check_virustotal(url, api_key):
    headers = {"x-apikey": api_key}
    params = {"url": url}
    try:
        print("🔍 Querying VirusTotal...")
        response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=params)
        if response.status_code == 200:
            analysis_url = response.json()["data"]["id"]
            full_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_url}"
            result = requests.get(full_url, headers=headers).json()
            stats = result["data"]["attributes"]["stats"]
            return stats
        else:
            return {"error": "VirusTotal request failed"}
    except Exception as e:
        return {"error": str(e)}

# ------------------ PDF Report ------------------ #
def export_pdf(report_data, filename="phishing_report.pdf"):
    if not PDF_ENABLED:
        print("⚠️ PDF export not available. Install fpdf using `pip install fpdf`.")
        return

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Phishing Link Analyzer Report", ln=True, align="C")
    pdf.ln()

    pdf.multi_cell(0, 10, f"URL: {report_data['url']}")
    pdf.multi_cell(0, 10, f"Verdict: {report_data['verdict']}")
    pdf.multi_cell(0, 10, f"Danger Score: {report_data['danger_score']}/100")
    pdf.ln()

    pdf.cell(200, 10, "Detected Features:", ln=True)
    for feat in report_data["features"]:
        pdf.multi_cell(0, 10, f"- {feat}")

    pdf.output(filename)
    print(f"📄 PDF report saved to {filename}")

# ------------------ CLI Interface ------------------ #
if __name__ == "__main__":
    print("🔗 Phishing Link Analyzer Tool 🔗")
    url = input("Enter the URL to analyze: ").strip()

    data = analyze_url(url)

    print("\n🔎 Analysis Result:")
    print(f"URL: {data['url']}")
    print(f"Verdict: {data['verdict']}")
    print(f"Score: {data['danger_score']}/100")

    if data['features']:
        print("\nPotential Red Flags:")
        for f in data['features']:
            print(f" - {f}")

    # Optional: VirusTotal
    use_vt = input("\nCheck with VirusTotal? (y/n): ").lower()
    if use_vt == 'y':
        api_key = input("Enter your VirusTotal API Key: ").strip()
        vt_result = check_virustotal(url, api_key)
        if "error" in vt_result:
            print("❌ VirusTotal Error:", vt_result["error"])
        else:
            print("🔬 VirusTotal Engine Detections:")
            print(f"  Harmless: {vt_result['harmless']}")
            print(f"  Malicious: {vt_result['malicious']}")
            print(f"  Suspicious: {vt_result['suspicious']}")

    # Optional: PDF Export
    if input("\nExport result to PDF? (y/n): ").lower() == 'y':
        export_pdf(data)
