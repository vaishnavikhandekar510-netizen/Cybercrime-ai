# 🛡️ CyberInvestigate AI

A full-stack cybersecurity-themed web app for a 50-mark college AI project. Dark neon-green
console theme, a **public complaint portal** (anyone can sign up and file/track a complaint)
completely separated from a **staff investigation backend** (Investigator / Police Officer /
Admin only) with rule-based "AI" analysis you can explain line-by-line in your viva.

---

## 🧰 Tech Stack

| Layer | Language | Used for |
|---|---|---|
| Backend / Server | **Python (Flask)** | Routing, database, role-based access control, all AI analysis logic, PDF generation |
| Database | **SQLite** | Users (staff + public), complaints/cases, evidence, timeline |
| Structure | **HTML (Jinja2 templates)** | All pages |
| Styling | **CSS** | Dark neon-green cybersecurity theme, 3D logo, mobile responsive |
| Interactivity | **JavaScript (Fetch API / AJAX)** | Live analysis without page reload, password show/hide, mobile menu |
| Reports | **Python (reportlab)** | Downloadable PDF investigation report (staff only) |

---

## 🌐 Two Separate Portals

### 1. Public Complaint Portal (`/`, `/login`, `/signup`)
Anyone can create an account and:
- File a cybercrime complaint (auto-categorized by the AI classifier)
- Track the status of their own complaints only
- Recover their username/password using their **registered mobile number** (OTP-based)

Public users **never** see the investigation backend, other people's complaints, evidence
analysis tools, or case management features.

### 2. Staff Investigation Backend (`/staff/login`)
Only Investigator / Police Officer / Admin accounts (which only you create/manage) can reach:
- Full case management, evidence upload & AI analysis, IP/log/chat/URL tools
- The evidence timeline, PDF report generator
- Dashboard stats, including **"Complaints Registered Today"** — a fully backend-only metric
- Password recovery via **security question** (appropriate since these are accounts you control)

No link on the public site ever points here — it's a separate URL only staff know.

---

## ▶️ How to Run

1. Install Python 3.9+ (if not already installed).
2. Open a terminal inside the `cybercrime-ai` folder.
3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
   (Use `py -m pip install -r requirements.txt` instead if `pip` isn't recognized on Windows.)
4. Run the server:
   ```
   python app.py
   ```
   (or `py app.py`)
5. Open your browser at: **http://127.0.0.1:5000**

### Optional: Friendlier local URL
Windows shows raw `127.0.0.1:5000` by default. To use a name instead of numbers:
1. Right-click `setup_custom_url.bat` → **Run as administrator**.
2. It adds `vaishnavis-cyberproject.local` to your hosts file.
3. Then visit **http://vaishnavis-cyberproject.local:5000** instead — same site, friendlier address.

(The port number `:5000` still appears because binding to the standard web port 80 requires
running the server as Administrator, which most college lab PCs won't allow — this is a normal
constraint for any local Flask project and worth mentioning honestly if asked in your viva.)

---

### 🔑 Demo Accounts

**Public complainant:**
| Username | Password | Phone (for OTP recovery) |
|---|---|---|
| `rahul_mehta` | `public123` | 9123456780 |

**Staff:**
| Role | Username | Password | Security Question | Answer |
|---|---|---|---|---|
| Investigator | `investigator` | `invest123` | What is your college name? | Jnan Vikas Mehta College |
| Police Officer | `officer` | `officer123` | What city do you work in? | Mumbai |
| Admin | `admin` | `admin123` | What is the name of this college project? | Cybercrime |

---

## ✅ Feature Checklist (mapped to your project steps)

- **Step 1 – Login:** Separate public login/signup and staff role-based login, show/hide password toggle, phone-OTP recovery (public) and security-question recovery (staff)
- **Step 2 – New/File Complaint:** Public complaint form (`file_complaint.html`) and staff-initiated case form (`new_case.html`)
- **Step 3 – Upload Evidence:** Staff-only, inside case detail
- **Step 4 – AI Analysis:** Phishing keyword scoring, fake URL detection, dangerous attachments — `analyze_evidence_text()` in `app.py`
- **Step 5 – Crime Classification:** Keyword-weighted category prediction — `classify_crime()` in `app.py`
- **Step 6 – IP Investigation:** Offline deterministic lookup — `investigate_ip()` in `app.py`
- **Step 7 – Log Analysis:** Brute force / SQLi / DDoS / port scan detection — `analyze_logs()` in `app.py`
- **Step 8 – Chat Analysis:** Scam/blackmail keyword scoring — `analyze_chat()` in `app.py`
- **Step 9 – URL Analysis:** HTTPS/TLD/keyword heuristics — `analyze_url()` in `app.py`
- **Step 10 – Evidence Timeline:** Auto-logged + manual entries, shown to both staff (full) and complainants (status-only)
- **Step 11 – AI PDF Report:** Staff-only, one-click PDF export — `build_pdf_report()` in `app.py`

---

## 🎓 Notes for Your Viva

- **Why simulated OTP instead of real SMS?** No SMS gateway (Twilio/MSG91 etc.) is configured
  for this offline classroom project — those require a paid account and internet access. The
  OTP is generated server-side and shown on-screen labelled "SIMULATED SMS" so the *logic* is
  real and demonstrable, while being honest that a production deployment would wire this to an
  actual SMS API instead of displaying the code.
- **Why security question for staff but OTP for public?** Staff accounts are few and
  owner-managed (you create them), so a security question is a reasonable, explainable choice.
  Public accounts are self-registered by strangers, so phone-based recovery matches how most
  real citizen-facing portals work.
- **Role separation** is enforced server-side with Python decorators (`@staff_required`,
  `@public_required`) — even if someone guesses a staff URL, the backend checks their session
  role before returning any data, not just hiding the link in the UI.
- Every AI module is rule-based, transparent keyword/pattern scoring — open `app.py` and you
  can point to the exact `+X points` rule that produced any score.

Good luck with your presentation! 🎉
