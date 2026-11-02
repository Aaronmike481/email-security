from pyproc_worker import expose, run_worker
import subprocess
import json
import dns.resolver
import requests
import time
import os
import base64 # <-- IMPORT ADDED
from fpdf import FPDF

# this checks for dmarcrecords
def dmarc_check(domain):
    try:
        result = subprocess.run(["checkdmarc", domain], capture_output=True, text=True)
        if result.returncode == 0:
            return json.loads(result.stdout)
    except Exception:
        pass
    return {"error": "Failed to check DMARC"}

#this checks for possible lookalike domains
def lookalike_domain(domain):
    if "." not in domain:
        return []
    base, tld = domain.rsplit('.', 1)
    typos = [f"{base}-secure.{tld}", domain.replace("o", "0"), domain.replace("l", "1")]
    found = []
    for typo in set(typos):
        try:
            dns.resolver.resolve(typo, 'A')
            found.append(typo)
        except Exception:
            pass
    return found

#this checks for the domain mx provider
def mx_proider(domain):
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_string = " ".join([str(mx.exchange).lower() for mx in mx_records])
        if "google" in mx_string: return "Google Workspace"
        if "outlook" in mx_string: return "Microsoft 365"
        return "Other"
    except Exception:
        return "Unknown"

# possible fixes
def generate_fixes(dmarc, lookalikes, breaches):
    fixes = []
    actions = []
    
    if not dmarc.get("dmarc", {}).get("record"):
        fixes.append("Add this TXT record to your DNS: 'v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com;'")
    elif "p=none" in dmarc.get("dmarc", {}).get("record", ""):
        fixes.append("Your DMARC is in monitor mode. Change to 'p=reject' to block spoofing.")
        
    if lookalikes:
        fixes.append(f"File a DMCA takedown against these domains: {', '.join(lookalikes)}")
        
    if breaches:
        actions.append(f"Force password reset for: {', '.join(breaches)} and enable MFA.")
        
    return fixes, actions

def generate_summary(domain, dmarc, lookalikes, breaches):
    issues = []
    severity = "SAFE"
    
    if not dmarc.get("dmarc", {}).get("record"):
        issues.append("missing DMARC protection (allowing email spoofing)")
        severity = "CRITICAL"
    elif "p=none" in dmarc.get("dmarc", {}).get("record", ""):
        issues.append("a weak DMARC policy (monitoring only, not blocking)")
        if severity != "CRITICAL": severity = "HIGH"
        
    if lookalikes:
        issues.append(f"{len(lookalikes)} lookalike domain(s) registered by potential attackers")
        if severity != "CRITICAL": severity = "HIGH"
        
    if breaches:
        issues.append(f"{len(breaches)} employee email(s) exposed in data breaches")
        if severity != "CRITICAL": severity = "HIGH"

    if not issues:
        summary = f"The email security posture for {domain} is strong. No critical vulnerabilities were detected in our scan."
    else:
        issue_text = ", ".join(issues[:-1]) + (" and " if len(issues) > 1 else "") + issues[-1]
        summary = f"The security assessment for {domain} revealed {issue_text}. Immediate remediation is recommended to prevent Business Email Compromise (BEC) attacks."

    return {"severity": severity, "executive_summary": summary}

# full pdf generator
def generate_pdf_report(domain, judge, fixes, actions):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_margins(10, 10, 10)
    
    pdf.set_font("Helvetica", 'B', 16)
    pdf.cell(0, 10, f"Security Report: {domain}", ln=True, align='C')
    pdf.ln(5)
    
    pdf.set_font("Helvetica", 'B', 12)
    severity = judge.get("severity", "UNKNOWN")
    pdf.cell(0, 10, f"Severity: {severity}", ln=True)
    
    pdf.set_font("Helvetica", size=11)
    summary = judge.get("executive_summary", "No summary available.")
    pdf.multi_cell(0, 8, summary)
    pdf.ln(10)
    
    pdf.set_font("Helvetica", 'B', 12)
    pdf.cell(0, 10, "Technical Fixes (We Provide):", ln=True)
    pdf.set_font("Helvetica", size=11)
    for fix in fixes:
        pdf.multi_cell(180, 8, f"- {fix}") 
    pdf.ln(5)
    
    pdf.set_font("Helvetica", 'B', 12)
    pdf.cell(0, 10, "Company Actions Required:", ln=True)
    pdf.set_font("Helvetica", size=11)
    for action in actions:
        pdf.multi_cell(180, 8, f"- {action}")
        
    safe_domain = "".join([c for c in domain if c.isalnum() or c in ".-_"])
    os.makedirs("reports", exist_ok=True)
    filename = f"reports/{safe_domain}_report.pdf"
    
    pdf.output(filename)


    with open(filename, "rb") as f:
        pdf_base64 = base64.b64encode(f.read()).decode('utf-8')

    return pdf_base64

@expose
def email_audit(req):
    domain = req.get("domain", "").strip()
    
    if "." not in domain:
        return {"error": "Invalid domain format"}
    
    dmarc = dmarc_check(domain)
    lookalikes = lookalike_domain(domain)
    provider = mx_proider(domain)
    
    auto_fixes, company_actions = generate_fixes(dmarc, lookalikes, [])
    judge = generate_summary(domain, dmarc, lookalikes, [])
    
    pdf_base64 = generate_pdf_report(domain, judge, auto_fixes, company_actions)
    
    return {
        "domain": domain,
        "provider": provider,
        "dmarc_data": dmarc,
        "lookalikes": lookalikes,
        "judge_verdict": judge,
        "auto_remediation": auto_fixes,
        "company_action": company_actions,
        "pdf_report": pdf_base64 
    }

if __name__ == "__main__":
    run_worker()