from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from email_validator import validate_email, EmailNotValidError
import dns.resolver
import socket

app = FastAPI(
    title="Disposable & Fake Email Detection API",
    description="Detect disposable, fake, and risky email addresses",
    version="1.0.0"
)

# Load disposable email domains
with open("disposable_domains.txt") as f:
    DISPOSABLE_DOMAINS = set(d.strip().lower() for d in f if d.strip())

class EmailRequest(BaseModel):
    email: str

def check_mx(domain: str) -> bool:
    try:
        dns.resolver.resolve(domain, "MX")
        return True
    except Exception:
        return False

def is_catch_all(domain: str) -> bool:
    try:
        test_email = f"randomtest123456@{domain}"
        mx_records = dns.resolver.resolve(domain, "MX")
        mx_record = str(mx_records[0].exchange)

        server = socket.create_connection((mx_record, 25), timeout=5)
        server.close()
        return True
    except Exception:
        return False

@app.post("/check-email")
def check_email(data: EmailRequest):
    try:
        valid = validate_email(data.email)
        domain = valid.domain.lower()
    except EmailNotValidError:
        raise HTTPException(status_code=400, detail="Invalid email format")

    disposable = domain in DISPOSABLE_DOMAINS
    mx_exists = check_mx(domain)
    catch_all = is_catch_all(domain) if mx_exists else False

    risk_score = 0
    reasons = []

    if disposable:
        risk_score += 70
        reasons.append("Disposable email provider")

    if not mx_exists:
        risk_score += 50
        reasons.append("Domain has no MX records")

    if catch_all:
        risk_score += 20
        reasons.append("Catch-all email domain")

    if risk_score >= 70:
        risk = "HIGH"
    elif risk_score >= 30:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        "email": data.email,
        "domain": domain,
        "valid_format": True,
        "disposable": disposable,
        "mx_exists": mx_exists,
        "catch_all": catch_all,
        "risk": risk,
        "risk_score": risk_score,
        "reasons": reasons
    }
