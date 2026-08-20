"""
================================================================
 AI CYBERCRIME INVESTIGATION ASSISTANT
 Backend Server  --  (PYTHON / FLASK)
================================================================
 This file is the "brain" of the project. It:
   1. Serves the HTML pages (Jinja2 templates)
   2. Stores data in a local SQLite database
   3. Runs all the rule-based "AI" analysis engines:
        - Evidence / Email phishing analysis
        - Cybercrime classification
        - IP investigation
        - Log file analysis (brute force / SQLi / DDoS / port scan)
        - Chat / message scam analysis
        - URL phishing analysis
        - Automatic evidence timeline
        - PDF report generation

 NOTE ON "AI": Every analysis engine below uses rule-based /
 keyword-weighted scoring (a technique real fraud-detection
 systems also use before/alongside ML). It is intentionally
 transparent so you can explain exactly how each score is
 produced in your viva. Comments mark each rule clearly.
================================================================
"""

import os
import re
import json
import sqlite3
import hashlib
import secrets
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, jsonify, flash, send_file, g
)
from werkzeug.utils import secure_filename
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
)
from reportlab.lib.units import cm

# ----------------------------------------------------------------
# APP CONFIG                                            (PYTHON)
# ----------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "cybercrime.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
REPORT_DIR = os.path.join(BASE_DIR, "reports")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)

app = Flask(__name__)
# Uses an env var if you set one (recommended for production), otherwise
# falls back to this fixed random key (already unique to your copy of the
# project - not a shared/public demo value). Do not commit a real
# production key to a public GitHub repo.
app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "5dc7c9a90a6d005bd62b0c8586487d5d7a128e2b3de1d1dda57b5375005ab2f9"
)

# ----------------------------------------------------------------
# OWNER PHONE NUMBER                                    (PYTHON)
# This is the ONLY phone number that can manage staff account
# credentials (create/change staff usernames & passwords). Anyone
# without this exact number cannot get past /staff/forgot-password,
# no matter what staff account they claim to be recovering.
# CHANGE THIS to your real 10-digit number before deploying.
# ----------------------------------------------------------------
OWNER_PHONE = "9999999999"  # <-- CHANGE THIS to your own phone number
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024  # 25 MB uploads

ALLOWED_EXTENSIONS = {
    "png", "jpg", "jpeg", "gif", "pdf", "txt", "log",
    "csv", "eml", "msg", "mp4", "mov", "json"
}
DANGEROUS_EXTENSIONS = {"exe", "scr", "bat", "js", "vbs", "jar", "cmd"}


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# ----------------------------------------------------------------
# DATABASE HELPERS                                      (PYTHON)
# ----------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        full_name TEXT,
        phone_number TEXT UNIQUE,
        security_question TEXT,
        security_answer_hash TEXT,
        otp_code TEXT,
        otp_expires_at TEXT
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS cases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id TEXT UNIQUE NOT NULL,
        victim_name TEXT,
        case_date TEXT,
        crime_type TEXT,
        description TEXT,
        predicted_category TEXT,
        status TEXT DEFAULT 'Registered',
        filed_by_username TEXT,
        created_by TEXT,
        created_at TEXT
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS evidence (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id TEXT NOT NULL,
        filename TEXT,
        evidence_type TEXT,
        risk_score INTEGER,
        findings TEXT,
        uploaded_at TEXT
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS timeline (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id TEXT NOT NULL,
        event_time TEXT,
        event_desc TEXT,
        source TEXT
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS analysis_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id TEXT,
        module TEXT,
        input_summary TEXT,
        result_summary TEXT,
        risk_score INTEGER,
        created_at TEXT
    )""")

    # default demo users (username / password / role / full name / phone / security Q&A)
    demo_users = [
        ("admin", "admin123", "Admin", "System Administrator", "9000000001",
         "What is the name of this college project?", "cybercrime"),
        ("investigator", "invest123", "Investigator", "Vaishnavi Khandekar", "9000000002",
         "What is your college name?", "jnan vikas mehta college"),
        ("officer", "officer123", "Police Officer", "Inspector A. Verma", "9000000003",
         "What city do you work in?", "mumbai"),
    ]
    for u, p, r, name, phone, question, answer in demo_users:
        pw_hash = hashlib.sha256(p.encode()).hexdigest()
        ans_hash = hashlib.sha256(answer.strip().lower().encode()).hexdigest()
        try:
            c.execute(
                """INSERT INTO users (username, password_hash, role, full_name, phone_number,
                   security_question, security_answer_hash) VALUES (?,?,?,?,?,?,?)""",
                (u, pw_hash, r, name, phone, question, ans_hash),
            )
        except sqlite3.IntegrityError:
            pass  # already exists

    # one demo public complainant account (for testing the public portal)
    try:
        c.execute(
            """INSERT INTO users (username, password_hash, role, full_name, phone_number)
               VALUES (?,?,?,?,?)""",
            ("rahul_mehta", hashlib.sha256("public123".encode()).hexdigest(),
             "Complainant", "Rahul Mehta", "9123456780"),
        )
    except sqlite3.IntegrityError:
        pass

    conn.commit()
    conn.close()


# ----------------------------------------------------------------
# AUTH DECORATORS                                       (PYTHON)
# ----------------------------------------------------------------
STAFF_ROLES = ("Investigator", "Police Officer", "Admin")


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("staff_login"))
        return f(*args, **kwargs)
    return wrapper


def staff_required(f):
    """Only Investigator / Police Officer / Admin can reach these routes.
    The public complaint portal never links here, and if a Complainant
    account somehow lands on a staff URL they are redirected back to
    their own portal - the investigation backend stays fully hidden
    from the public.                                       (PYTHON)"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("staff_login"))
        if session.get("role") not in STAFF_ROLES:
            flash("That area is for authorized staff only.", "error")
            return redirect(url_for("my_complaints"))
        return f(*args, **kwargs)
    return wrapper


def public_required(f):
    """Only logged-in Complainant (public) accounts.               (PYTHON)"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("public_login"))
        if session.get("role") != "Complainant":
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return wrapper


# ==================================================================
#  AI / RULE-BASED ANALYSIS ENGINES                      (PYTHON)
# ==================================================================

# ---- STEP 4: Evidence / Email Phishing Analysis -----------------
PHISHING_KEYWORDS = [
    "verify your account", "urgent action required", "click here",
    "suspended", "confirm your password", "lottery", "you have won",
    "bank account blocked", "update your details", "limited time",
    "otp", "one time password", "gift card", "wire transfer",
    "unusual activity", "security alert", "act now"
]
SUSPICIOUS_TLDS = [".xyz", ".top", ".club", ".info", ".biz", ".ru", ".tk"]
DANGEROUS_ATTACH = {"exe", "scr", "bat", "js", "vbs", "jar", "docm", "xlsm"}


def analyze_evidence_text(text, filename=""):
    """Scores an email / text evidence for phishing indicators."""
    text_l = (text or "").lower()
    score = 0
    findings = []

    # Rule 1: phishing keyword matches
    matched_kw = [k for k in PHISHING_KEYWORDS if k in text_l]
    if matched_kw:
        pts = min(40, len(matched_kw) * 8)
        score += pts
        findings.append(f"Suspicious phishing phrases detected: {', '.join(matched_kw[:5])} (+{pts})")

    # Rule 2: fake / suspicious URLs
    urls = re.findall(r"https?://[^\s\"'<>]+", text)
    fake_urls = []
    for u in urls:
        if any(tld in u.lower() for tld in SUSPICIOUS_TLDS) or re.search(r"\d+\.\d+\.\d+\.\d+", u):
            fake_urls.append(u)
    if fake_urls:
        score += 25
        findings.append(f"Fake / suspicious URL(s) found: {', '.join(fake_urls[:3])} (+25)")
    elif urls:
        score += 5
        findings.append("Contains external link(s) - flagged for review (+5)")

    # Rule 3: suspicious sender pattern (email spoofing look-alike)
    sender_match = re.search(r"from[:\s]+([\w\.-]+@[\w\.-]+)", text_l)
    if sender_match:
        sender = sender_match.group(1)
        if re.search(r"(support|security|admin|bank).*\d", sender) or "-" in sender.split("@")[0]:
            score += 15
            findings.append(f"Suspicious sender address pattern: {sender} (+15)")

    # Rule 4: dangerous attachment extension in filename/text
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext in DANGEROUS_ATTACH:
        score += 20
        findings.append(f"Dangerous attachment type (.{ext}) detected (+20)")

    # Rule 5: urgency / pressure language
    if re.search(r"\b(immediately|within 24 hours|final notice|last warning)\b", text_l):
        score += 10
        findings.append("Urgency / pressure language detected (+10)")

    score = min(100, score)
    if not findings:
        findings.append("No strong phishing indicators found in provided text.")

    verdict = "High Risk - Likely Phishing" if score >= 70 else \
              "Medium Risk - Suspicious" if score >= 35 else "Low Risk"

    return {
        "risk_score": score,
        "verdict": verdict,
        "findings": findings,
        "urls_found": urls,
    }


# ---- STEP 5: Cybercrime Classification ---------------------------
CRIME_CATEGORIES = {
    "Online Banking Fraud": ["otp", "bank", "debited", "upi", "atm", "netbanking", "credit card", "debit card", "transaction"],
    "Social Media Account Takeover": ["instagram", "facebook", "hacked", "account", "twitter", "snapchat", "profile", "unauthorized login"],
    "Phishing Attack": ["phishing", "fake link", "click link", "verify account", "spoofed email"],
    "Identity Theft": ["identity", "aadhaar", "pan card", "impersonat", "fake profile using my"],
    "Cyberstalking / Harassment": ["stalking", "harass", "threat", "following me online", "blackmail"],
    "Financial / UPI Fraud": ["upi fraud", "paytm", "gpay", "phonepe", "fake payment", "refund scam"],
    "Ransomware / Malware Attack": ["ransomware", "encrypted my files", "malware", "virus", "trojan"],
    "Job / Investment Scam": ["job offer", "investment", "crypto scam", "trading scam", "work from home scam"],
    "Cyberbullying": ["bully", "abusive messages", "mock", "humiliate online"],
    "Data Breach": ["data leak", "database hacked", "leaked data", "breach"],
}


def classify_crime(description):
    desc_l = (description or "").lower()
    scores = {}
    for category, keywords in CRIME_CATEGORIES.items():
        hits = sum(1 for k in keywords if k in desc_l)
        if hits:
            scores[category] = hits
    if not scores:
        return {"category": "Uncategorized / Needs Manual Review", "confidence": 0, "scores": {}}

    best = max(scores, key=scores.get)
    total_hits = sum(scores.values())
    confidence = round((scores[best] / total_hits) * 100) if total_hits else 0
    confidence = max(confidence, 60)  # floor for a matched category
    return {"category": best, "confidence": confidence, "scores": scores}


# ---- STEP 6: IP Investigation ------------------------------------
BLACKLISTED_IPS = {"185.220.101.5", "45.155.205.1", "94.102.61.7", "192.42.116.16"}
COUNTRY_BY_PREFIX = {
    "1": "India", "2": "India", "3": "USA", "4": "USA", "5": "Russia",
    "6": "Germany", "7": "China", "8": "USA", "9": "India",
}


def investigate_ip(ip):
    """
    NOTE: This runs fully offline using deterministic local heuristics
    (no external threat-intel API call), so it works without internet
    access and is safe/reproducible for classroom demos.
    """
    ip = ip.strip()
    is_valid = bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", ip))
    if not is_valid:
        return {"error": "Invalid IPv4 address format."}

    octets = [int(x) for x in ip.split(".")]
    private = (
        octets[0] == 10 or
        (octets[0] == 172 and 16 <= octets[1] <= 31) or
        (octets[0] == 192 and octets[1] == 168) or
        octets[0] == 127
    )

    # deterministic pseudo-lookup so demo results are always identical
    seed = sum(octets)
    country = COUNTRY_BY_PREFIX.get(str(octets[0])[0], "Unknown / Unassigned")
    isps = ["Reliance Jio", "Airtel", "BSNL", "Vodafone Idea", "Amazon AWS", "DigitalOcean", "Google Cloud", "Unknown ISP"]
    isp = "Private / Local Network" if private else isps[seed % len(isps)]

    blacklisted = ip in BLACKLISTED_IPS
    vpn_detected = (not private) and (seed % 5 == 0)

    risk = "Low"
    risk_score = 10
    if blacklisted:
        risk, risk_score = "High", 90
    elif vpn_detected:
        risk, risk_score = "Medium", 55
    elif private:
        risk, risk_score = "N/A (Internal Network)", 0

    return {
        "ip": ip,
        "is_private": private,
        "country": "Internal Network" if private else country,
        "isp": isp,
        "blacklisted": blacklisted,
        "vpn_detected": vpn_detected,
        "risk": risk,
        "risk_score": risk_score,
    }


# ---- STEP 7: Log Analysis -----------------------------------------
def analyze_logs(log_text):
    lines = log_text.splitlines()
    findings = []
    ip_fail_counts = {}
    sqli_hits = 0
    portscan_hits = 0
    ip_request_counts = {}

    sqli_pattern = re.compile(r"(\bunion\s+select\b|'--|\bor\s+1=1\b|drop\s+table|<script)", re.I)
    fail_pattern = re.compile(r"(failed password|authentication failure|401|invalid user)", re.I)
    scan_pattern = re.compile(r"(nmap|port scan|SYN_SCAN|connection refused)", re.I)
    ip_pattern = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

    for line in lines:
        ip_match = ip_pattern.search(line)
        ip = ip_match.group(1) if ip_match else "unknown"

        if fail_pattern.search(line):
            ip_fail_counts[ip] = ip_fail_counts.get(ip, 0) + 1
        if sqli_pattern.search(line):
            sqli_hits += 1
        if scan_pattern.search(line):
            portscan_hits += 1
        if ip != "unknown":
            ip_request_counts[ip] = ip_request_counts.get(ip, 0) + 1

    threats = []
    score = 0

    brute_force_ips = {ip: n for ip, n in ip_fail_counts.items() if n >= 4}
    if brute_force_ips:
        score += 35
        threats.append({
            "type": "Brute Force Attack",
            "detail": f"{len(brute_force_ips)} IP(s) with repeated failed logins: " +
                      ", ".join(f"{ip} ({n} attempts)" for ip, n in list(brute_force_ips.items())[:5])
        })

    if sqli_hits:
        score += 30
        threats.append({"type": "SQL Injection Attempt", "detail": f"{sqli_hits} suspicious query pattern(s) detected"})

    ddos_ips = {ip: n for ip, n in ip_request_counts.items() if n >= 20}
    if ddos_ips:
        score += 25
        threats.append({
            "type": "Possible DDoS Activity",
            "detail": f"Abnormally high request volume from: " + ", ".join(list(ddos_ips.keys())[:5])
        })

    if portscan_hits:
        score += 15
        threats.append({"type": "Port Scanning", "detail": f"{portscan_hits} scan signature(s) detected"})

    score = min(100, score)
    if not threats:
        threats.append({"type": "No Major Threat", "detail": "No brute force, SQLi, DDoS, or scan signatures found."})

    return {"risk_score": score, "threats": threats, "lines_analyzed": len(lines)}


# ---- STEP 8: Chat / Message Analysis ------------------------------
SCAM_PHRASES = {
    "send otp": 25, "share otp": 25, "click this link": 20, "click here": 15,
    "lottery winner": 30, "you have won": 25, "urgent": 10, "act now": 12,
    "bank details": 20, "kyc update": 18, "blocked account": 15,
    "free gift": 15, "investment opportunity": 15, "double your money": 25,
    "pay processing fee": 20, "blackmail": 30, "leak your photos": 30,
    "transfer money": 15, "gift card code": 20,
}


def analyze_chat(text):
    text_l = (text or "").lower()
    score = 0
    matched = []
    for phrase, weight in SCAM_PHRASES.items():
        if phrase in text_l:
            score += weight
            matched.append(phrase)

    score = min(100, score)
    category = "Blackmail / Extortion" if any(p in matched for p in ["blackmail", "leak your photos"]) else \
               "Financial Scam" if score >= 40 else \
               "Suspicious Message" if score >= 15 else "Likely Safe"

    return {
        "risk_score": score,
        "confidence": score,
        "matched_phrases": matched,
        "category": category,
        "verdict": "Possible Scam" if score >= 40 else ("Needs Review" if score >= 15 else "No Scam Indicators"),
    }


# ---- STEP 9: URL Analysis ------------------------------------------
SUSPICIOUS_URL_WORDS = ["login", "verify", "secure", "update", "bank", "free", "prize", "confirm", "account", "win"]


def analyze_url(url):
    url_l = url.lower().strip()
    score = 0
    findings = []

    if not url_l.startswith("https://"):
        score += 20
        findings.append("No HTTPS encryption (+20)")

    if re.search(r"\d+\.\d+\.\d+\.\d+", url_l):
        score += 25
        findings.append("URL uses raw IP address instead of domain (+25)")

    hyphen_count = url_l.count("-")
    if hyphen_count >= 2:
        score += 15
        findings.append(f"Excessive hyphens in domain ({hyphen_count}) (+15)")

    if any(tld in url_l for tld in SUSPICIOUS_TLDS):
        score += 15
        findings.append("Suspicious top-level domain (+15)")

    word_hits = [w for w in SUSPICIOUS_URL_WORDS if w in url_l]
    if len(word_hits) >= 2:
        score += 20
        findings.append(f"Multiple suspicious keywords in URL: {', '.join(word_hits)} (+20)")

    if len(url_l) > 75:
        score += 10
        findings.append("Unusually long URL (+10)")

    # mock "domain age" - deterministic pseudo value from hash
    domain_age_days = (hashlib.md5(url_l.encode()).digest()[0]) * 3
    if domain_age_days < 90:
        score += 15
        findings.append(f"Newly registered domain (~{domain_age_days} days old) (+15)")

    score = min(100, score)
    if not findings:
        findings.append("No suspicious indicators found.")

    risk = "High" if score >= 60 else "Medium" if score >= 30 else "Low"
    return {"risk_score": score, "risk": risk, "findings": findings, "domain_age_days": domain_age_days}


# ==================================================================
#  ROUTES                                                (PYTHON)
# ==================================================================

@app.route("/")
def home():
    if "username" in session:
        return redirect(url_for("dashboard") if session.get("role") in STAFF_ROLES else url_for("my_complaints"))
    return render_template("landing.html")


# ==================================================================
#  PUBLIC PORTAL (Complainants)                          (PYTHON)
#  File a complaint / track status. No access to the investigation
#  backend (AI tools, other people's cases, evidence, reports).
# ==================================================================
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        phone_number = request.form.get("phone_number", "").strip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not re.match(r"^[6-9]\d{9}$", phone_number):
            flash("Please enter a valid 10-digit Indian mobile number.", "error")
            return render_template("signup.html")
        if len(password) < 6:
            flash("Password must be at least 6 characters long.", "error")
            return render_template("signup.html")

        db = get_db()
        pw_hash = hashlib.sha256(password.encode()).hexdigest()
        try:
            db.execute(
                "INSERT INTO users (username, password_hash, role, full_name, phone_number) VALUES (?,?,?,?,?)",
                (username, pw_hash, "Complainant", full_name, phone_number),
            )
            db.commit()
            flash("Account created successfully! Please log in.", "success")
            return redirect(url_for("public_login"))
        except sqlite3.IntegrityError:
            flash("That username or phone number is already registered.", "error")

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def public_login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username=? AND role='Complainant'", (username,)
        ).fetchone()
        if user and user["password_hash"] == hashlib.sha256(password.encode()).hexdigest():
            session["username"] = user["username"]
            session["role"] = user["role"]
            session["full_name"] = user["full_name"]
            return redirect(url_for("my_complaints"))
        flash("Invalid username or password.", "error")
    return render_template("public_login.html")


# ---- PUBLIC FORGOT USERNAME / PASSWORD (via phone number) --------------
# No real SMS gateway is configured for this offline classroom project, so
# this simulates an OTP by displaying it on-screen (clearly labelled as a
# simulation). In a real deployment this generated code would be sent via
# an SMS API (e.g. Twilio/MSG91) instead of being shown on the page.
@app.route("/forgot-access", methods=["GET", "POST"])
def forgot_access():
    if request.method == "POST":
        phone_number = request.form.get("phone_number", "").strip()
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE phone_number=? AND role='Complainant'", (phone_number,)
        ).fetchone()
        if not user:
            flash("No account found with that phone number.", "error")
            return render_template("forgot_access.html")

        otp = str(secrets.randbelow(900000) + 100000)  # 6-digit OTP
        expires = (datetime.now() + timedelta(minutes=10)).isoformat()
        db.execute("UPDATE users SET otp_code=?, otp_expires_at=? WHERE username=?",
                   (otp, expires, user["username"]))
        db.commit()
        session["otp_phone"] = phone_number
        flash(f"SIMULATED SMS: Your OTP is {otp} (valid 10 minutes). "
              f"A real deployment would text this to your phone instead of showing it here.", "success")
        return redirect(url_for("verify_otp"))

    return render_template("forgot_access.html")


@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    phone_number = session.get("otp_phone")
    if not phone_number:
        return redirect(url_for("forgot_access"))

    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE phone_number=? AND role='Complainant'", (phone_number,)
    ).fetchone()
    if not user:
        session.pop("otp_phone", None)
        return redirect(url_for("forgot_access"))

    if request.method == "POST":
        entered_otp = request.form.get("otp", "").strip()
        action = request.form.get("action")  # 'recover_username' or 'reset_password'

        if entered_otp != user["otp_code"] or datetime.now() > datetime.fromisoformat(user["otp_expires_at"]):
            flash("Incorrect or expired OTP. Please request a new one.", "error")
            return render_template("verify_otp.html")

        if action == "recover_username":
            flash(f"Your username is: {user['username']}", "success")
            session.pop("otp_phone", None)
            return redirect(url_for("public_login"))

        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")
        if len(new_password) < 6:
            flash("New password must be at least 6 characters long.", "error")
            return render_template("verify_otp.html")
        if new_password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template("verify_otp.html")

        new_hash = hashlib.sha256(new_password.encode()).hexdigest()
        db.execute("UPDATE users SET password_hash=?, otp_code=NULL WHERE username=?",
                   (new_hash, user["username"]))
        db.commit()
        session.pop("otp_phone", None)
        flash("Password reset successful! You can now log in.", "success")
        return redirect(url_for("public_login"))

    return render_template("verify_otp.html")


# ---- FILE A COMPLAINT (public, maps onto Step 2 New Case internally) ---
@app.route("/file-complaint", methods=["GET", "POST"])
@public_required
def file_complaint():
    if request.method == "POST":
        db = get_db()
        db_count = db.execute("SELECT COUNT(*) as n FROM cases").fetchone()["n"]
        case_id = f"CC-{datetime.now().year}-{str(db_count + 1).zfill(3)}"
        crime_type = request.form.get("crime_type")
        description = request.form.get("description").strip()
        classification = classify_crime(description)

        db.execute(
            """INSERT INTO cases (case_id, victim_name, case_date, crime_type, description,
               predicted_category, status, filed_by_username, created_by, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (case_id, session["full_name"], datetime.now().strftime("%Y-%m-%d"), crime_type,
             description, classification["category"], "Registered", session["username"],
             session["username"], datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
        db.execute(
            "INSERT INTO timeline (case_id, event_time, event_desc, source) VALUES (?,?,?,?)",
            (case_id, datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
             "Complaint filed by complainant and registered in system", "Public Portal")
        )
        db.commit()
        flash(f"Complaint filed successfully! Your Complaint ID is {case_id}. "
              f"Our AI system has categorized it as: {classification['category']}", "success")
        return redirect(url_for("my_complaints"))

    return render_template("file_complaint.html")


@app.route("/my-complaints")
@public_required
def my_complaints():
    db = get_db()
    complaints = db.execute(
        "SELECT * FROM cases WHERE filed_by_username=? ORDER BY created_at DESC",
        (session["username"],)
    ).fetchall()
    return render_template("my_complaints.html", complaints=complaints)


@app.route("/my-complaints/<case_id>")
@public_required
def my_complaint_detail(case_id):
    db = get_db()
    case = db.execute(
        "SELECT * FROM cases WHERE case_id=? AND filed_by_username=?",
        (case_id, session["username"])
    ).fetchone()
    if not case:
        flash("Complaint not found.", "error")
        return redirect(url_for("my_complaints"))
    timeline = db.execute("SELECT * FROM timeline WHERE case_id=? ORDER BY event_time", (case_id,)).fetchall()
    return render_template("my_complaint_detail.html", case=case, timeline=timeline)


@app.route("/logout")
def logout():
    was_staff = session.get("role") in STAFF_ROLES
    session.clear()
    return redirect(url_for("staff_login") if was_staff else url_for("home"))


# ==================================================================
#  STAFF PORTAL (Investigator / Police Officer / Admin)  (PYTHON)
#  Full investigation backend - never linked from the public site.
# ==================================================================
@app.route("/staff/login", methods=["GET", "POST"])
def staff_login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role")

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username=? AND role=?", (username, role)
        ).fetchone()

        if user and user["password_hash"] == hashlib.sha256(password.encode()).hexdigest():
            session["username"] = user["username"]
            session["role"] = user["role"]
            session["full_name"] = user["full_name"]
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username, password, or role.", "error")

    return render_template("staff_login.html")


# ---- STAFF ACCOUNT MANAGEMENT (owner-phone-locked) ----------------------
# Only OWNER_PHONE can get past this gate. Verifying it unlocks a panel
# where any staff account's username/password can be changed. No security
# question, no "which account" guesswork - one phone number controls
# everything, matching how a single-owner backend should work.
def owner_verified_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        verified_until = session.get("owner_verified_until")
        if not verified_until or datetime.now() > datetime.fromisoformat(verified_until):
            flash("Please verify your phone number to manage staff accounts.", "error")
            return redirect(url_for("staff_forgot_password"))
        return f(*args, **kwargs)
    return wrapper


@app.route("/staff/forgot-password", methods=["GET", "POST"])
def staff_forgot_password():
    if request.method == "POST":
        phone_number = request.form.get("phone_number", "").strip()

        if phone_number != OWNER_PHONE:
            # Deliberately vague - never confirms/denies which numbers are valid.
            flash("This phone number is not authorized to manage staff accounts.", "error")
            return render_template("staff_forgot_password.html")

        otp = str(secrets.randbelow(900000) + 100000)  # 6-digit OTP
        session["owner_otp"] = otp
        session["owner_otp_expires"] = (datetime.now() + timedelta(minutes=10)).isoformat()
        flash(f"SIMULATED SMS: Your OTP is {otp} (valid 10 minutes). "
              f"A real deployment would text this to your phone instead of showing it here.", "success")
        return redirect(url_for("staff_verify_owner_otp"))

    return render_template("staff_forgot_password.html")


@app.route("/staff/verify-owner-otp", methods=["GET", "POST"])
def staff_verify_owner_otp():
    if "owner_otp" not in session:
        return redirect(url_for("staff_forgot_password"))

    if request.method == "POST":
        entered_otp = request.form.get("otp", "").strip()
        if entered_otp != session["owner_otp"] or datetime.now() > datetime.fromisoformat(session["owner_otp_expires"]):
            flash("Incorrect or expired OTP. Please request a new one.", "error")
            return render_template("staff_verify_owner_otp.html")

        session.pop("owner_otp", None)
        session.pop("owner_otp_expires", None)
        session["owner_verified_until"] = (datetime.now() + timedelta(minutes=15)).isoformat()
        flash("Phone number verified. You can now manage staff accounts.", "success")
        return redirect(url_for("staff_manage_accounts"))

    return render_template("staff_verify_owner_otp.html")


@app.route("/staff/manage-accounts")
@owner_verified_required
def staff_manage_accounts():
    db = get_db()
    accounts = db.execute(
        "SELECT username, role, full_name FROM users WHERE role IN (?,?,?) ORDER BY role, username",
        STAFF_ROLES
    ).fetchall()
    return render_template("staff_manage_accounts.html", accounts=accounts)


@app.route("/staff/manage-accounts/<username>/edit", methods=["GET", "POST"])
@owner_verified_required
def staff_edit_account(username):
    db = get_db()
    account = db.execute(
        "SELECT * FROM users WHERE username=? AND role IN (?,?,?)",
        (username, *STAFF_ROLES)
    ).fetchone()
    if not account:
        flash("Staff account not found.", "error")
        return redirect(url_for("staff_manage_accounts"))

    if request.method == "POST":
        new_username = request.form.get("new_username", "").strip()
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not new_username:
            flash("Username cannot be empty.", "error")
            return render_template("staff_edit_account.html", account=account)

        if new_password or confirm_password:
            if len(new_password) < 6:
                flash("New password must be at least 6 characters long.", "error")
                return render_template("staff_edit_account.html", account=account)
            if new_password != confirm_password:
                flash("Passwords do not match.", "error")
                return render_template("staff_edit_account.html", account=account)

        try:
            if new_password:
                new_hash = hashlib.sha256(new_password.encode()).hexdigest()
                db.execute("UPDATE users SET username=?, password_hash=? WHERE username=?",
                           (new_username, new_hash, username))
            else:
                db.execute("UPDATE users SET username=? WHERE username=?",
                           (new_username, username))
            db.commit()
            flash(f"Account updated successfully.", "success")
            return redirect(url_for("staff_manage_accounts"))
        except sqlite3.IntegrityError:
            flash("That username is already taken.", "error")
            return render_template("staff_edit_account.html", account=account)

    return render_template("staff_edit_account.html", account=account)


# ---- STAFF DASHBOARD (fully backend - never seen by the public) --------
@app.route("/dashboard")
@staff_required
def dashboard():
    db = get_db()
    cases = db.execute("SELECT * FROM cases ORDER BY created_at DESC").fetchall()
    today_str = datetime.now().strftime("%Y-%m-%d")
    stats = {
        "total": len(cases),
        "open": len([c for c in cases if c["status"] not in ("Closed",)]),
        "closed": len([c for c in cases if c["status"] == "Closed"]),
        "high_risk": db.execute(
            "SELECT COUNT(*) as n FROM evidence WHERE risk_score >= 70"
        ).fetchone()["n"],
        "today": len([c for c in cases if c["created_at"].startswith(today_str)]),
    }
    return render_template("dashboard.html", cases=cases, stats=stats)


# ---- STEP 2: NEW CASE (staff-initiated, distinct from public filing) ---
@app.route("/case/new", methods=["GET", "POST"])
@staff_required
def new_case():
    if request.method == "POST":
        db = get_db()
        case_id = request.form.get("case_id").strip()
        victim = request.form.get("victim_name").strip()
        date = request.form.get("case_date")
        crime_type = request.form.get("crime_type")
        description = request.form.get("description").strip()

        classification = classify_crime(description)

        try:
            db.execute(
                """INSERT INTO cases (case_id, victim_name, case_date, crime_type,
                   description, predicted_category, created_by, created_at)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (case_id, victim, date, crime_type, description,
                 classification["category"], session["username"],
                 datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            )
            db.execute(
                "INSERT INTO timeline (case_id, event_time, event_desc, source) VALUES (?,?,?,?)",
                (case_id, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "Case created and registered in system", "System")
            )
            db.commit()
            flash(f"Case {case_id} created. AI predicted category: {classification['category']}", "success")
            return redirect(url_for("case_detail", case_id=case_id))
        except sqlite3.IntegrityError:
            flash("Case ID already exists. Please use a unique Case ID.", "error")

    suggested_id = f"CC-{datetime.now().year}-{str(len(get_db().execute('SELECT * FROM cases').fetchall())+1).zfill(3)}"
    return render_template("new_case.html", suggested_id=suggested_id)


# ---- CASE DETAIL / STEP 3 UPLOAD / STEP 10 TIMELINE / STEP 11 REPORT ---
@app.route("/case/<case_id>")
@staff_required
def case_detail(case_id):
    db = get_db()
    case = db.execute("SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone()
    if not case:
        flash("Case not found.", "error")
        return redirect(url_for("dashboard"))
    evidence = db.execute("SELECT * FROM evidence WHERE case_id=? ORDER BY uploaded_at", (case_id,)).fetchall()
    timeline = db.execute("SELECT * FROM timeline WHERE case_id=? ORDER BY event_time", (case_id,)).fetchall()
    return render_template("case_detail.html", case=case, evidence=evidence, timeline=timeline)


@app.route("/case/<case_id>/upload", methods=["POST"])
@staff_required
def upload_evidence(case_id):
    db = get_db()
    file = request.files.get("evidence_file")
    text_content = request.form.get("text_content", "")
    evidence_type = request.form.get("evidence_type", "Other")

    filename = ""
    saved_text = text_content

    if file and file.filename:
        filename = secure_filename(file.filename)
        save_path = os.path.join(UPLOAD_DIR, f"{case_id}_{filename}")
        file.save(save_path)
        # try reading text-based files for analysis
        if filename.rsplit(".", 1)[-1].lower() in {"txt", "log", "csv", "eml", "json"}:
            try:
                with open(save_path, "r", errors="ignore") as f:
                    saved_text = f.read()
            except Exception:
                saved_text = text_content

    # Run STEP 4 AI analysis on whatever text we have
    result = analyze_evidence_text(saved_text or "", filename)

    db.execute(
        """INSERT INTO evidence (case_id, filename, evidence_type, risk_score, findings, uploaded_at)
           VALUES (?,?,?,?,?,?)""",
        (case_id, filename or "(pasted text)", evidence_type, result["risk_score"],
         json.dumps(result["findings"]), datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    db.execute(
        "INSERT INTO timeline (case_id, event_time, event_desc, source) VALUES (?,?,?,?)",
        (case_id, datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
         f"Evidence uploaded ({evidence_type}) - Risk Score {result['risk_score']}%", "Evidence Upload")
    )
    db.commit()

    return jsonify({"success": True, "analysis": result})


# ---- STEP 6: IP INVESTIGATION (AJAX)  ----(PYTHON logic / JS calls it)---
@app.route("/api/ip-check", methods=["POST"])
@staff_required
def api_ip_check():
    data = request.get_json()
    result = investigate_ip(data.get("ip", ""))
    return jsonify(result)


# ---- STEP 7: LOG ANALYSIS (AJAX) ---------------------------------------
@app.route("/api/log-analysis", methods=["POST"])
@staff_required
def api_log_analysis():
    log_text = ""
    if "log_file" in request.files and request.files["log_file"].filename:
        log_text = request.files["log_file"].read().decode(errors="ignore")
    else:
        log_text = request.form.get("log_text", "")
    result = analyze_logs(log_text)
    return jsonify(result)


# ---- STEP 8: CHAT ANALYSIS (AJAX) --------------------------------------
@app.route("/api/chat-analysis", methods=["POST"])
@staff_required
def api_chat_analysis():
    data = request.get_json()
    result = analyze_chat(data.get("text", ""))
    return jsonify(result)


# ---- STEP 9: URL ANALYSIS (AJAX) ---------------------------------------
@app.route("/api/url-analysis", methods=["POST"])
@staff_required
def api_url_analysis():
    data = request.get_json()
    result = analyze_url(data.get("url", ""))
    return jsonify(result)


# ---- Standalone analysis tool pages ------------------------------------
@app.route("/tools/ip-check")
@staff_required
def tools_ip():
    return render_template("ip_check.html")


@app.route("/tools/log-analysis")
@staff_required
def tools_log():
    return render_template("log_analysis.html")


@app.route("/tools/chat-analysis")
@staff_required
def tools_chat():
    return render_template("chat_analysis.html")


@app.route("/tools/url-analysis")
@staff_required
def tools_url():
    return render_template("url_analysis.html")


# ---- STEP 10: Add manual timeline event ---------------------------------
@app.route("/case/<case_id>/timeline/add", methods=["POST"])
@staff_required
def add_timeline_event(case_id):
    db = get_db()
    event_time = request.form.get("event_time")
    event_desc = request.form.get("event_desc")
    db.execute(
        "INSERT INTO timeline (case_id, event_time, event_desc, source) VALUES (?,?,?,?)",
        (case_id, event_time, event_desc, "Manual Entry")
    )
    db.commit()
    return redirect(url_for("case_detail", case_id=case_id))


# ---- STEP 11: AI REPORT GENERATOR (PDF) ----------------------------------
@app.route("/case/<case_id>/report")
@staff_required
def generate_report(case_id):
    db = get_db()
    case = db.execute("SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone()
    evidence = db.execute("SELECT * FROM evidence WHERE case_id=?", (case_id,)).fetchall()
    timeline = db.execute("SELECT * FROM timeline WHERE case_id=? ORDER BY event_time", (case_id,)).fetchall()

    if not case:
        flash("Case not found.", "error")
        return redirect(url_for("dashboard"))

    avg_risk = round(sum(e["risk_score"] for e in evidence) / len(evidence)) if evidence else 0
    overall = "HIGH RISK" if avg_risk >= 70 else "MEDIUM RISK" if avg_risk >= 35 else "LOW RISK"

    pdf_path = os.path.join(REPORT_DIR, f"{case_id}_report.pdf")
    build_pdf_report(pdf_path, case, evidence, timeline, avg_risk, overall)

    return send_file(pdf_path, as_attachment=True, download_name=f"{case_id}_Investigation_Report.pdf")


def build_pdf_report(path, case, evidence, timeline, avg_risk, overall):
    """Builds the professional PDF report.                (PYTHON - reportlab)"""
    doc = SimpleDocTemplate(path, pagesize=A4, topMargin=1.5 * cm, bottomMargin=1.5 * cm)
    styles = getSampleStyleSheet()
    navy = colors.HexColor("#0d1b3e")
    blue = colors.HexColor("#1565c0")

    title_style = ParagraphStyle("title", parent=styles["Title"], textColor=navy, fontSize=20)
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], textColor=blue, spaceBefore=14)
    normal = styles["Normal"]

    elements = []
    elements.append(Paragraph("AI Cybercrime Investigation Report", title_style))
    elements.append(Paragraph(f"Generated on {datetime.now().strftime('%d %B %Y, %I:%M %p')}", normal))
    elements.append(Spacer(1, 16))

    elements.append(Paragraph("1. Case Summary", h2))
    case_table = Table([
        ["Case ID", case["case_id"]],
        ["Victim Name", case["victim_name"]],
        ["Date Reported", case["case_date"]],
        ["Reported Crime Type", case["crime_type"]],
        ["AI Predicted Category", case["predicted_category"]],
        ["Status", case["status"]],
        ["Investigating Officer", case["created_by"]],
    ], colWidths=[5 * cm, 10 * cm])
    case_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e8eefc")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    elements.append(case_table)
    elements.append(Spacer(1, 6))
    elements.append(Paragraph(f"<b>Description:</b> {case['description']}", normal))

    elements.append(Paragraph("2. Evidence &amp; AI Analysis Findings", h2))
    if evidence:
        ev_rows = [["Filename", "Type", "Risk Score", "Key Findings"]]
        for e in evidence:
            findings = json.loads(e["findings"]) if e["findings"] else []
            ev_rows.append([e["filename"], e["evidence_type"], f"{e['risk_score']}%", "; ".join(findings[:2])])
        ev_table = Table(ev_rows, colWidths=[3.5 * cm, 3 * cm, 2.5 * cm, 6 * cm])
        ev_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), navy),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        elements.append(ev_table)
    else:
        elements.append(Paragraph("No evidence uploaded for this case.", normal))

    elements.append(Paragraph("3. Evidence Timeline", h2))
    if timeline:
        tl_rows = [["Time", "Event", "Source"]]
        for t in timeline:
            tl_rows.append([t["event_time"], t["event_desc"], t["source"]])
        tl_table = Table(tl_rows, colWidths=[4 * cm, 8 * cm, 3 * cm])
        tl_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), blue),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
        ]))
        elements.append(tl_table)

    elements.append(Paragraph("4. Overall Risk Assessment", h2))
    risk_color = colors.red if overall == "HIGH RISK" else colors.orange if overall == "MEDIUM RISK" else colors.green
    elements.append(Paragraph(
        f"<b>Average Risk Score:</b> {avg_risk}% &nbsp;&nbsp; <b>Overall Assessment:</b> "
        f"<font color='{risk_color.hexval() if hasattr(risk_color,'hexval') else '#000'}'>{overall}</font>",
        normal
    ))

    elements.append(Paragraph("5. AI Recommendations", h2))
    recs = []
    if avg_risk >= 70:
        recs = [
            "Escalate case to senior cybercrime officer immediately.",
            "Freeze / flag associated bank or financial accounts if applicable.",
            "Preserve all digital evidence with proper chain of custody.",
            "Issue advisory to victim about further contact from suspects.",
        ]
    elif avg_risk >= 35:
        recs = [
            "Continue detailed manual investigation of flagged evidence.",
            "Cross-verify IP and URL findings with additional sources.",
            "Interview victim for further details.",
        ]
    else:
        recs = [
            "Low risk indicators - monitor for further complaints.",
            "Educate victim on general cyber-safety practices.",
        ]
    for r in recs:
        elements.append(Paragraph(f"• {r}", normal))

    elements.append(Paragraph("6. Conclusion", h2))
    elements.append(Paragraph(
        f"Based on AI-assisted analysis of the submitted evidence, this case has been "
        f"provisionally classified under <b>{case['predicted_category']}</b> with an overall "
        f"risk level of <b>{overall}</b>. This report was generated with the assistance of "
        f"automated rule-based analysis and should be reviewed by an authorized investigating "
        f"officer before further legal action.",
        normal
    ))

    doc.build(elements)


# ----------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    print("=" * 60)
    print(" CyberInvestigate AI - Starting Server")
    print(" Public site:  http://127.0.0.1:5000/          (file a complaint)")
    print(" Staff login:  http://127.0.0.1:5000/staff/login")
    print("-" * 60)
    print(" Demo Public Account: rahul_mehta / public123")
    print(" Demo Staff Accounts:")
    print("   admin / admin123          (Admin)")
    print("   investigator / invest123  (Investigator)")
    print("   officer / officer123      (Police Officer)")
    print("=" * 60)
    app.run(debug=True, host="0.0.0.0", port=5000)
