from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from models.user import db, User, URLScan

from urllib.parse import urlparse
from datetime import datetime, timedelta
from dotenv import load_dotenv

import requests
import os
import re
from google import genai


# ==========================================
# ENVIRONMENT
# ==========================================

load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

if GEMINI_API_KEY:
    gemini_client = genai.Client(api_key=GEMINI_API_KEY)
else:
    gemini_client = None


# ==========================================
# FLASK APPLICATION
# ==========================================

app = Flask(__name__)

app.secret_key = "sentinel-ai-xdr-secret-key"

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///sentinel.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)


# ==========================================
# GOOGLE SAFE BROWSING
# ==========================================

SAFE_BROWSING_API_KEY = os.getenv(
    "SAFE_BROWSING_API_KEY"
)


def check_safe_browsing(url):

    print("SAFE BROWSING FUNCTION CALLED")
    print(
        "API KEY LOADED:",
        bool(SAFE_BROWSING_API_KEY)
    )

    # API key missing
    if not SAFE_BROWSING_API_KEY:

        print(
            "SAFE BROWSING ERROR: "
            "API key not configured"
        )

        return {
            "checked": False,
            "safe": None,
            "matches": [],
            "message": (
                "Safe Browsing API key "
                "is not configured."
            )
        }

    api_url = (
        "https://safebrowsing.googleapis.com/v4/"
        "threatMatches:find"
    )

    payload = {

        "client": {
            "clientId": "sentinel-ai-xdr",
            "clientVersion": "1.0"
        },

        "threatInfo": {

            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],

            "platformTypes": [
                "ANY_PLATFORM"
            ],

            "threatEntryTypes": [
                "URL"
            ],

            "threatEntries": [
                {
                    "url": url
                }
            ]
        }
    }

    try:

        response = requests.post(

            api_url,

            params={
                "key": SAFE_BROWSING_API_KEY
            },

            json=payload,

            timeout=10
        )

        print(
            "SAFE BROWSING STATUS:",
            response.status_code
        )

        print(
            "SAFE BROWSING RAW RESPONSE:",
            response.text
        )

        response.raise_for_status()

        data = response.json()

        # ======================================
        # THREAT DETECTED
        # ======================================

        if data.get("matches"):

            threats = []

            for match in data["matches"]:

                threats.append({

                    "threat_type": match.get(
                        "threatType",
                        "UNKNOWN"
                    ),

                    "platform": match.get(
                        "platformType",
                        "UNKNOWN"
                    )
                })

            return {

                "checked": True,

                "safe": False,

                "matches": threats
            }

        # ======================================
        # NO THREAT DETECTED
        # ======================================

        return {

            "checked": True,

            "safe": True,

            "matches": []
        }

    except requests.RequestException as error:

        print(
            "SAFE BROWSING API ERROR:",
            error
        )

        if error.response is not None:

            print(
                "API RESPONSE:",
                error.response.text
            )

        return {

            "checked": False,

            "safe": None,

            "matches": [],

            "message": str(error)
        }


# ==========================================
# HOME
# ==========================================

@app.route("/")
def home():

    return render_template(
        "index.html"
    )


# ==========================================
# REGISTER
# ==========================================

@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():

    if request.method == "POST":

        name = request.form.get(
            "name",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        if (
            not name
            or not email
            or not password
            or not confirm_password
        ):

            return "All fields are required!"

        if password != confirm_password:

            return "Passwords do not match!"

        existing_user = User.query.filter_by(
            email=email
        ).first()

        if existing_user:

            return (
                "An account with this email "
                "already exists!"
            )

        hashed_password = generate_password_hash(
            password
        )

        new_user = User(

            name=name,

            email=email,

            password=hashed_password
        )

        db.session.add(new_user)

        db.session.commit()

        return redirect(
            url_for("login")
        )

    return render_template(
        "register.html"
    )


# ==========================================
# LOGIN
# ==========================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        user = User.query.filter_by(
            email=email
        ).first()

        if (
            user
            and check_password_hash(
                user.password,
                password
            )
        ):

            session["user_id"] = user.id

            session["user_name"] = user.name

            session["user_email"] = user.email

            return redirect(
                url_for("dashboard")
            )

        return "Invalid email or password!"

    return render_template(
        "login.html"
    )


# ==========================================
# DASHBOARD
# ==========================================

@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:

        return redirect(
            url_for("login")
        )

    user_id = session["user_id"]

    scans = URLScan.query.filter_by(

        user_id=user_id

    ).order_by(

        URLScan.created_at.desc()

    ).all()

    total_scans = len(scans)

    active_threats = sum(

        1

        for scan in scans

        if scan.verdict
        in [
            "SUSPICIOUS",
            "HIGH RISK"
        ]
    )

    high_risk = sum(

        1

        for scan in scans

        if scan.verdict == "HIGH RISK"
    )

    blocked_threats = high_risk

    # ======================================
    # SECURITY SCORE
    # ======================================

    if total_scans == 0:

        security_score = 100

    else:

        average_risk = sum(

            scan.score

            for scan in scans

        ) / total_scans

        security_score = round(

            max(
                0,
                100 - average_risk
            )
        )

    recent_scans = scans[:5]

    # ======================================
    # THREAT LEVEL
    # ======================================

    if not scans:

        threat_level = "LOW"

    elif high_risk > 0:

        threat_level = "CRITICAL"

    elif active_threats >= 3:

        threat_level = "HIGH"

    elif active_threats > 0:

        threat_level = "MEDIUM"

    else:

        threat_level = "LOW"

    # ======================================
    # CHART
    # ======================================

    today = datetime.utcnow().date()

    chart_labels = []

    chart_data = []

    for i in range(6, -1, -1):

        day = today - timedelta(
            days=i
        )

        count = 0

        for scan in scans:

            if scan.created_at:

                if scan.created_at.date() == day:

                    count += 1

        chart_labels.append(
            day.strftime("%a")
        )

        chart_data.append(
            count
        )

    return render_template(

        "dashboard.html",

        user_name=session[
            "user_name"
        ],

        total_scans=total_scans,

        active_threats=active_threats,

        high_risk=high_risk,

        blocked_threats=blocked_threats,

        security_score=security_score,

        threat_level=threat_level,

        chart_labels=chart_labels,

        chart_data=chart_data,

        recent_scans=recent_scans
    )
# ==========================================
# SETTINGS
# ==========================================

@app.route("/settings")
def settings():

    if "user_id" not in session:
        return redirect(url_for("login"))

    user = User.query.get(session["user_id"])

    return render_template(
        "settings.html",
        user=user
    )


# ==========================================
# LOGOUT
# ==========================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# ==========================================
# URL SCANNER
# ==========================================

@app.route(
    "/url-scanner",
    methods=["GET", "POST"]
)
def url_scanner():

    if "user_id" not in session:

        return redirect(
            url_for("login")
        )

    result = None

    if request.method == "POST":

        url = request.form.get(
            "url",
            ""
        ).strip()

        # ==================================
        # EMPTY URL
        # ==================================

        if not url:

            result = {

                "error":
                "Please enter a URL."
            }

        else:

            # ==================================
            # ADD HTTPS IF MISSING
            # ==================================

            if not url.startswith(
                (
                    "http://",
                    "https://"
                )
            ):

                url = "https://" + url

            parsed = urlparse(url)

            hostname = parsed.hostname or ""

            score = 0

            findings = []

            # ==================================
            # HTTPS CHECK
            # ==================================

            if parsed.scheme == "https":

                findings.append(
                    "HTTPS connection detected."
                )

            else:

                score += 15

                findings.append(
                    "URL is not using HTTPS."
                )

            # ==================================
            # IP ADDRESS CHECK
            # ==================================

            ip_pattern = (
                r"^\d{1,3}"
                r"(\.\d{1,3}){3}$"
            )

            if re.match(
                ip_pattern,
                hostname
            ):

                score += 25

                findings.append(
                    "URL uses an IP address "
                    "instead of a domain."
                )

            # ==================================
            # URL LENGTH CHECK
            # ==================================

            if len(url) > 100:

                score += 10

                findings.append(
                    "Unusually long URL detected."
                )

            # ==================================
            # @ SYMBOL CHECK
            # ==================================

            if "@" in url:

                score += 20

                findings.append(
                    "Suspicious @ character detected."
                )

            # ==================================
            # SUBDOMAIN CHECK
            # ==================================

            if hostname.count(".") >= 3:

                score += 10

                findings.append(
                    "Large number of subdomains "
                    "detected."
                )

            # ==================================
            # GOOGLE SAFE BROWSING
            # ==================================

            safe_browsing_result = (
                check_safe_browsing(url)
            )

            # Defaults
            safe_browsing_checked = (
                safe_browsing_result.get(
                    "checked",
                    False
                )
            )

            safe_browsing_safe = (
                safe_browsing_result.get(
                    "safe"
                )
            )

            safe_browsing_threats = (
                safe_browsing_result.get(
                    "matches",
                    []
                )
            )

            # ==================================
            # SAFE BROWSING RESULT
            # ==================================

            if safe_browsing_checked:

                # ------------------------------
                # THREAT DETECTED
                # ------------------------------

                if safe_browsing_safe is False:

                    score += 60

                    for threat in (
                        safe_browsing_threats
                    ):

                        threat_type = (
                            threat.get(
                                "threat_type",
                                "UNKNOWN"
                            )
                        )

                        findings.append(

                            "Google Safe Browsing "
                            "detected: "
                            + threat_type
                        )

                # ------------------------------
                # NO THREAT
                # ------------------------------

                else:

                    findings.append(

                        "Google Safe Browsing: "
                        "No known threat detected."
                    )

            # ==================================
            # API CHECK FAILED
            # ==================================

            else:

                findings.append(

                    "Google Safe Browsing check "
                    "could not be completed."
                )

            # ==================================
            # SUSPICIOUS KEYWORDS
            # ==================================

            suspicious_words = [

                "login",
                "verify",
                "account",
                "update",
                "secure",
                "password",
                "bank",
                "confirm"
            ]

            found_words = []

            for word in suspicious_words:

                if word in url.lower():

                    found_words.append(
                        word
                    )

            if found_words:

                score += min(

                    len(found_words) * 5,

                    20
                )

                findings.append(

                    "Suspicious keywords found: "
                    + ", ".join(found_words)
                )

            # ==================================
            # LIMIT SCORE
            # ==================================

            score = min(
                score,
                100
            )

            # ==================================
            # VERDICT
            # ==================================

            if score >= 60:

                verdict = "HIGH RISK"

                level = "high"

            elif score >= 30:

                verdict = "SUSPICIOUS"

                level = "medium"

            else:

                verdict = "SAFE"

                level = "safe"

            # ==================================
            # RESULT FOR HTML
            # ==================================

            result = {

                "url": url,

                "score": score,

                "verdict": verdict,

                "level": level,

                "findings": findings,

                "safe_browsing_checked":
                    safe_browsing_checked,

                "safe_browsing_safe":
                    safe_browsing_safe,

                "safe_browsing_threats":
                    safe_browsing_threats
            }

            # ==================================
            # CONVERT THREATS TO TEXT
            # ==================================

            threat_text = ""

            if safe_browsing_threats:

                threat_names = []

                for threat in (
                    safe_browsing_threats
                ):

                    if isinstance(
                        threat,
                        dict
                    ):

                        threat_names.append(

                            threat.get(
                                "threat_type",
                                "UNKNOWN"
                            )
                        )

                    else:

                        threat_names.append(
                            str(threat)
                        )

                threat_text = ", ".join(
                    threat_names
                )

            # ==================================
            # SAVE SCAN TO DATABASE
            # ==================================

            scan = URLScan(

                user_id=session[
                    "user_id"
                ],

                url=url,

                score=score,

                verdict=verdict,

                findings="\n".join(
                    findings
                ),

                safe_browsing_checked=(
                    safe_browsing_checked
                ),

                safe_browsing_safe=(
                    safe_browsing_safe
                ),

                safe_browsing_threats=(
                    threat_text
                )
            )

            db.session.add(scan)

            db.session.commit()

    return render_template(

        "url_scanner.html",

        result=result
    )
 # ==========================================
# PHISHING DETECTOR
# ==========================================

@app.route("/phishing-detector", methods=["GET", "POST"])
def phishing_detector():

    if "user_id" not in session:
        return redirect(url_for("login"))

    result = None

    if request.method == "POST":

        url = request.form.get("url", "").strip()

        if not url:
            result = {
                "error": "Please enter a URL."
            }

        else:

            if not url.startswith(("http://", "https://")):
                url = "https://" + url

            parsed = urlparse(url)

            hostname = parsed.hostname or ""

            score = 0
            findings = []

            # ==================================
            # HTTPS
            # ==================================

            if parsed.scheme == "https":

                findings.append(
                    "HTTPS connection detected."
                )

            else:

                score += 15

                findings.append(
                    "URL is not using HTTPS."
                )

            # ==================================
            # IP ADDRESS
            # ==================================

            ip_pattern = (
                r"^\d{1,3}"
                r"(\.\d{1,3}){3}$"
            )

            if re.match(ip_pattern, hostname):

                score += 25

                findings.append(
                    "URL uses an IP address instead of a domain."
                )

            # ==================================
            # URL LENGTH
            # ==================================

            if len(url) > 100:

                score += 10

                findings.append(
                    "Unusually long URL detected."
                )

            # ==================================
            # @ SYMBOL
            # ==================================

            if "@" in url:

                score += 20

                findings.append(
                    "Suspicious @ character detected."
                )

            # ==================================
            # MANY SUBDOMAINS
            # ==================================

            if hostname.count(".") >= 3:

                score += 10

                findings.append(
                    "Large number of subdomains detected."
                )

            # ==================================
            # SUSPICIOUS KEYWORDS
            # ==================================

            suspicious_words = [
                "login",
                "verify",
                "verification",
                "account",
                "update",
                "secure",
                "security",
                "password",
                "bank",
                "confirm",
                "signin",
                "payment",
                "wallet",
                "authenticate"
            ]

            found_words = []

            for word in suspicious_words:

                if word in url.lower():

                    found_words.append(word)

            if found_words:

                score += min(
                    len(found_words) * 5,
                    25
                )

                findings.append(
                    "Suspicious keywords found: "
                    + ", ".join(found_words)
                )

            # ==================================
            # SUSPICIOUS TLD
            # ==================================

            suspicious_tlds = [
                ".xyz",
                ".top",
                ".click",
                ".buzz",
                ".work",
                ".zip",
                ".tk",
                ".ml",
                ".ga",
                ".cf",
                ".gq"
            ]

            suspicious_tld_found = False

            for tld in suspicious_tlds:

                if hostname.lower().endswith(tld):

                    suspicious_tld_found = True
                    break

            if suspicious_tld_found:

                score += 15

                findings.append(
                    "Potentially suspicious top-level domain detected."
                )

            # ==================================
            # HYPHEN CHECK
            # ==================================

            if hostname.count("-") >= 2:

                score += 10

                findings.append(
                    "Multiple hyphens detected in domain name."
                )

            # ==================================
            # GOOGLE SAFE BROWSING
            # ==================================

            safe_browsing_result = check_safe_browsing(url)

            if safe_browsing_result["checked"]:

                if safe_browsing_result["safe"] is False:

                    score += 60

                    findings.append(
                        "Google Safe Browsing detected a known threat."
                    )

                    for threat in safe_browsing_result.get(
                        "matches",
                        []
                    ):

                        threat_type = threat.get(
                            "threat_type",
                            "UNKNOWN"
                        )

                        findings.append(
                            "Threat type: " + threat_type
                        )

                else:

                    findings.append(
                        "Google Safe Browsing: "
                        "No known threat detected."
                    )

            else:

                findings.append(
                    "Google Safe Browsing check "
                    "could not be completed."
                )

            # ==================================
            # FINAL SCORE
            # ==================================

            score = min(score, 100)

            # ==================================
            # VERDICT
            # ==================================

            if score >= 60:

                verdict = "HIGH RISK"
                level = "high"

            elif score >= 30:

                verdict = "SUSPICIOUS"
                level = "medium"

            else:

                verdict = "SAFE"
                level = "safe"

            # ==================================
            # RESULT
            # ==================================

            result = {
                "url": url,
                "score": score,
                "verdict": verdict,
                "level": level,
                "findings": findings
            }
                        # ==================================
            # SAVE PHISHING SCAN TO DATABASE
            # ==================================

            threat_text = ""

            if safe_browsing_result.get("matches"):
                threat_names = []

                for threat in safe_browsing_result["matches"]:
                    threat_names.append(
                        threat.get("threat_type", "UNKNOWN")
                    )

                threat_text = ", ".join(threat_names)

            scan = URLScan(
                user_id=session["user_id"],
                url=url,
                score=score,
                verdict=verdict,
                findings="\n".join(findings),
                safe_browsing_checked=safe_browsing_result.get(
                    "checked", False
                ),
                safe_browsing_safe=safe_browsing_result.get(
                    "safe"
                ),
                safe_browsing_threats=threat_text
            )

            db.session.add(scan)
            db.session.commit()

    return render_template(
        "phishing_detector.html",
        result=result
    )
# ==========================================
# SENTINEL AI - SECURITY CONTEXT
# ==========================================

def get_security_context(user_id):

    scans = URLScan.query.filter_by(
        user_id=user_id
    ).order_by(
        URLScan.created_at.desc()
    ).limit(10).all()

    if not scans:
        return "No security scans are available for this user."

    context = []

    for index, scan in enumerate(scans, start=1):

        context.append(
            f"""
Scan #{index}
URL: {scan.url}
Risk Score: {scan.score}/100
Verdict: {scan.verdict}
Created At: {scan.created_at}
Findings:
{scan.findings or "No findings available."}

Google Safe Browsing Checked:
{scan.safe_browsing_checked}

Google Safe Browsing Safe:
{scan.safe_browsing_safe}

Google Safe Browsing Threats:
{scan.safe_browsing_threats or "None"}
"""
        )

    return "\n".join(context)
def analyze_password(password):

    import math
    import re

    findings = []
    suggestions = []

    # -----------------------------
    # BASIC CHARACTER CHECKS
    # -----------------------------

    length = len(password)

    uppercase = len(re.findall(r"[A-Z]", password))
    lowercase = len(re.findall(r"[a-z]", password))
    numbers = len(re.findall(r"[0-9]", password))
    special = len(re.findall(r"[^A-Za-z0-9]", password))

    score = 0

    # Length
    if length >= 8:
        score += 20
        findings.append("Good password length detected.")
    else:
        findings.append("Password should contain at least 8 characters.")
        suggestions.append("Use at least 8 characters.")

    if length >= 12:
        score += 15
        findings.append("Excellent password length detected.")
    else:
        suggestions.append("Use 12 or more characters for better security.")

    # Uppercase
    if uppercase > 0:
        score += 15
        findings.append("Uppercase letter detected.")
    else:
        findings.append("Add at least one uppercase letter.")
        suggestions.append("Add uppercase letters such as A-Z.")

    # Lowercase
    if lowercase > 0:
        score += 15
        findings.append("Lowercase letter detected.")
    else:
        findings.append("Add at least one lowercase letter.")
        suggestions.append("Add lowercase letters such as a-z.")

    # Numbers
    if numbers > 0:
        score += 15
        findings.append("Number detected.")
    else:
        findings.append("Add at least one number.")
        suggestions.append("Add numbers such as 0-9.")

    # Special characters
    if special > 0:
        score += 20
        findings.append("Special character detected.")
    else:
        findings.append("Add at least one special character.")
        suggestions.append("Add symbols such as ! @ # $ %.")

    # -----------------------------
    # COMMON PASSWORD CHECK
    # -----------------------------

    common_passwords = {
        "password",
        "password123",
        "123456",
        "12345678",
        "123456789",
        "1234567890",
        "qwerty",
        "qwerty123",
        "admin",
        "admin123",
        "letmein",
        "welcome",
        "abc123",
        "iloveyou",
        "monkey",
        "dragon"
    }

    if password.lower() in common_passwords:

        score = min(score, 20)

        findings.insert(
            0,
            "⚠ This password is commonly used and should be avoided."
        )

        suggestions.insert(
            0,
            "Use a unique password that is not based on common patterns."
        )

        common_password = True

    else:

        findings.append(
            "✓ Password does not match the basic common-password list."
        )

        common_password = False

    # -----------------------------
    # REPEATED CHARACTERS
    # -----------------------------

    if re.search(r"(.)\1\1", password):

        findings.append(
            "Repeated character pattern detected."
        )

        suggestions.append(
            "Avoid repeating the same character multiple times."
        )

    # -----------------------------
    # SIMPLE SEQUENCES
    # -----------------------------

    weak_sequences = [
        "1234",
        "abcd",
        "qwerty",
        "asdf",
        "password"
    ]

    password_lower = password.lower()

    if any(sequence in password_lower for sequence in weak_sequences):

        findings.append(
            "Common sequence or predictable pattern detected."
        )

        suggestions.append(
            "Avoid predictable sequences such as 1234 or qwerty."
        )

    # -----------------------------
    # ENTROPY ESTIMATE
    # -----------------------------

    pool = 0

    if uppercase:
        pool += 26

    if lowercase:
        pool += 26

    if numbers:
        pool += 10

    if special:
        pool += 32

    if pool > 0 and length > 0:
        entropy = round(length * math.log2(pool), 2)
    else:
        entropy = 0

    # -----------------------------
    # VERDICT
    # -----------------------------

    if common_password:

        verdict = "WEAK"

    elif score >= 80:

        verdict = "STRONG"

    elif score >= 60:

        verdict = "MODERATE"

    else:

        verdict = "WEAK"

    # -----------------------------
    # CRACK RESISTANCE
    # -----------------------------

    if entropy < 40:
        crack_resistance = "Very weak"

    elif entropy < 60:
        crack_resistance = "Weak"

    elif entropy < 80:
        crack_resistance = "Strong"

    else:
        crack_resistance = "Very strong"

    # -----------------------------
    # FINAL RECOMMENDATION
    # -----------------------------

    if verdict == "STRONG":

        recommendation = (
            "This password has good security characteristics. "
            "Keep it unique and avoid reusing it."
        )

    elif verdict == "MODERATE":

        recommendation = (
            "This password is reasonably strong, but adding "
            "more length and character variety would improve it."
        )

    else:

        recommendation = (
            "This password should be strengthened before being "
            "used for an important account."
        )

    return {
        "score": score,
        "verdict": verdict,

        "length": length,
        "uppercase": uppercase,
        "lowercase": lowercase,
        "numbers": numbers,
        "special": special,

        "entropy": entropy,

        "crack_time": crack_resistance,

        "common_password": common_password,

        "findings": findings,

        "suggestions": suggestions,

        "recommendation": recommendation
    }

@app.route("/password-auditor", methods=["GET", "POST"])
def password_auditor():

    if "user_id" not in session:
        return redirect(url_for("login"))

    result = None

    if request.method == "POST":

        password = request.form.get("password", "")

        if not password:

            result = {
                "error": "Please enter a password."
            }

        else:

            result = analyze_password(password)

    return render_template(
        "password_auditor.html",
        result=result
    )

# ==========================================
# FILE SCANNER
# ==========================================

@app.route("/file-scanner", methods=["GET", "POST"])
def file_scanner():

    if "user_id" not in session:
        return redirect(url_for("login"))

    result = None

    if request.method == "POST":

        uploaded_file = request.files.get("file")

        if uploaded_file is None:
            result = {
                "error": "No file was received."
            }

        elif uploaded_file.filename == "":
            result = {
                "error": "Please select a file."
            }

        else:

            filename = uploaded_file.filename

            # File extension
            extension = os.path.splitext(filename)[1].lower()

            # File size
            uploaded_file.seek(0, os.SEEK_END)
            file_size = uploaded_file.tell()
            uploaded_file.seek(0)

            # SHA-256
            import hashlib

            sha256 = hashlib.sha256()

            while True:

                chunk = uploaded_file.read(8192)

                if not chunk:
                    break

                sha256.update(chunk)

            file_hash = sha256.hexdigest()

            # File size display
            if file_size < 1024:

                size_display = f"{file_size} Bytes"

            elif file_size < 1024 * 1024:

                size_display = f"{file_size / 1024:.2f} KB"

            else:

                size_display = (
                    f"{file_size / (1024 * 1024):.2f} MB"
                )

            # File type
            file_types = {

                ".txt": "Text File",
                ".pdf": "PDF Document",

                ".doc": "Word Document",
                ".docx": "Word Document",

                ".xls": "Excel Spreadsheet",
                ".xlsx": "Excel Spreadsheet",

                ".ppt": "PowerPoint",
                ".pptx": "PowerPoint",

                ".jpg": "Image",
                ".jpeg": "Image",
                ".png": "Image",
                ".gif": "Image",

                ".mp3": "Audio",
                ".wav": "Audio",

                ".mp4": "Video",
                ".avi": "Video",
                ".mkv": "Video",

                ".zip": "ZIP Archive",
                ".rar": "RAR Archive",
                ".7z": "7Z Archive",

                ".py": "Python Source Code",
                ".java": "Java Source Code",
                ".js": "JavaScript Source Code",

                ".html": "HTML Document",
                ".css": "CSS Stylesheet",

                ".exe": "Windows Executable",
                ".msi": "Windows Installer",

                ".bat": "Batch Script",
                ".cmd": "Command Script",

                ".ps1": "PowerShell Script",
                ".vbs": "VBScript"
            }

            file_type = file_types.get(
                extension,
                "Unknown File Type"
            )

            # ==================================
            # SECURITY ANALYSIS
            # ==================================

            score = 0
            findings = []

            dangerous_extensions = {
                ".exe",
                ".msi",
                ".bat",
                ".cmd",
                ".ps1",
                ".vbs",
                ".scr",
                ".com"
            }

            suspicious_extensions = {
                ".zip",
                ".rar",
                ".7z"
            }

            # Dangerous extension

            if extension in dangerous_extensions:

                score += 70

                findings.append(
                    "Executable or script file detected."
                )

                findings.append(
                    "This file type may execute commands."
                )

            # Archive

            elif extension in suspicious_extensions:

                score += 25

                findings.append(
                    "Compressed archive detected."
                )

                findings.append(
                    "Archives may contain executable files."
                )

            else:

                findings.append(
                    "No inherently executable file extension detected."
                )

            # Large file

            if file_size > 100 * 1024 * 1024:

                score += 10

                findings.append(
                    "Large file size detected."
                )

            # Double extension

            suspicious_names = [
                ".pdf.exe",
                ".doc.exe",
                ".docx.exe",
                ".jpg.exe",
                ".png.exe",
                ".txt.exe"
            ]

            filename_lower = filename.lower()

            for pattern in suspicious_names:

                if filename_lower.endswith(pattern):

                    score += 30

                    findings.append(
                        "Suspicious double file extension detected."
                    )

                    break

            # Invoice executable

            if (
                "invoice" in filename_lower
                and extension in dangerous_extensions
            ):

                score += 10

                findings.append(
                    "Filename looks like a document "
                    "but uses an executable extension."
                )

            # Limit score

            score = min(score, 100)

            # Verdict

            if score >= 60:

                verdict = "HIGH RISK"

                recommendation = (
                    "Do not execute this file unless "
                    "you completely trust its source."
                )

            elif score >= 30:

                verdict = "SUSPICIOUS"

                recommendation = (
                    "Treat this file with caution and "
                    "verify its source before opening it."
                )

            else:

                verdict = "SAFE"

                recommendation = (
                    "No major risk indicators were found "
                    "from the basic file characteristics."
                )

            # Final result

            result = {

                "filename": filename,

                "extension": (
                    extension
                    if extension
                    else "None"
                ),

                "size": size_display,

                "hash": file_hash,

                "file_type": file_type,

                "score": score,

                "verdict": verdict,

                "findings": findings,

                "recommendation": recommendation
            }

    return render_template(
        "file_scanner.html",
        result=result
    )
# ==========================================
# THREATS
# ==========================================

@app.route("/threats")
def threats():

    if "user_id" not in session:
        return redirect(url_for("login"))

    scans = URLScan.query.filter_by(
        user_id=session["user_id"]
    ).filter(
        URLScan.verdict.in_([
            "SUSPICIOUS",
            "HIGH RISK"
        ])
    ).order_by(
        URLScan.created_at.desc()
    ).all()

    return render_template(
        "threats.html",
        scans=scans
    )

# ==========================================
# REPORTS
# ==========================================

@app.route("/reports")
def reports():

    if "user_id" not in session:
        return redirect(url_for("login"))

    scans = URLScan.query.filter_by(
        user_id=session["user_id"]
    ).order_by(
        URLScan.created_at.desc()
    ).all()

    # Statistics
    total_scans = len(scans)

    safe_scans = sum(
        1
        for scan in scans
        if scan.verdict == "SAFE"
    )

    suspicious_scans = sum(
        1
        for scan in scans
        if scan.verdict == "SUSPICIOUS"
    )

    high_risk_scans = sum(
        1
        for scan in scans
        if scan.verdict == "HIGH RISK"
    )

    # Average security risk score
    if total_scans > 0:

        average_score = round(
            sum(scan.score for scan in scans)
            / total_scans
        )

    else:

        average_score = 0

    return render_template(
        "reports.html",

        scans=scans,

        total_scans=total_scans,

        safe_scans=safe_scans,

        suspicious_scans=suspicious_scans,

        high_risk_scans=high_risk_scans,

        average_score=average_score
    )
# ==========================================
# ANALYTICS
# ==========================================

@app.route("/analytics")
def analytics():

    if "user_id" not in session:
        return redirect(url_for("login"))

    scans = URLScan.query.filter_by(
        user_id=session["user_id"]
    ).order_by(
        URLScan.created_at.desc()
    ).all()

    total_scans = len(scans)

    safe_scans = sum(
        1 for scan in scans
        if scan.verdict == "SAFE"
    )

    suspicious_scans = sum(
        1 for scan in scans
        if scan.verdict == "SUSPICIOUS"
    )

    high_risk_scans = sum(
        1 for scan in scans
        if scan.verdict == "HIGH RISK"
    )

    # Average score
    if total_scans > 0:
        average_score = round(
            sum(scan.score for scan in scans)
            / total_scans
        )
    else:
        average_score = 0

    # ==============================
    # LAST 7 DAYS
    # ==============================

    today = datetime.utcnow().date()

    chart_labels = []
    chart_data = []

    for i in range(6, -1, -1):

        day = today - timedelta(days=i)

        count = sum(
            1
            for scan in scans
            if scan.created_at
            and scan.created_at.date() == day
        )

        chart_labels.append(
            day.strftime("%a")
        )

        chart_data.append(count)

    return render_template(
        "analytics.html",

        scans=scans,

        total_scans=total_scans,

        safe_scans=safe_scans,

        suspicious_scans=suspicious_scans,

        high_risk_scans=high_risk_scans,

        average_score=average_score,

        chart_labels=chart_labels,

        chart_data=chart_data
    )
# ==========================================
# AI ASSISTANT
# ==========================================

@app.route("/ai-assistant", methods=["GET", "POST"])
def ai_assistant():

    if "user_id" not in session:
        return redirect(url_for("login"))

    answer = None
    error = None
    question = ""

    if request.method == "POST":

        question = request.form.get(
            "question",
            ""
        ).strip()

        print("==========================================")
        print("SENTINEL AI REQUEST")
        print("QUESTION:", question)

        # --------------------------------------
        # EMPTY QUESTION
        # --------------------------------------

        if not question:

            error = "Please enter a question."

            print("ERROR: Empty question")

        # --------------------------------------
        # GEMINI NOT CONFIGURED
        # --------------------------------------

        elif gemini_client is None:

            error = "Gemini API key is not configured."

            print("ERROR: Gemini client is not configured.")

        else:

            try:

                # --------------------------------------
                # GET USER SECURITY DATA
                # --------------------------------------

                security_context = get_security_context(
                    session["user_id"]
                )

                print("Security context loaded.")

                # --------------------------------------
                # SENTINEL SYSTEM PROMPT
                # --------------------------------------

                prompt = f"""
You are Sentinel AI, the cybersecurity assistant
inside the Sentinel AI XDR security platform.

Your job is to help the authenticated user understand
their security activity and provide safe cybersecurity
guidance.

IMPORTANT RULES:

1. Never reveal passwords or sensitive credentials.
2. Do not invent scan results.
3. Only use the provided Sentinel scan data when
   discussing the user's scans.
4. Clearly distinguish between facts from Sentinel
   and general cybersecurity advice.
5. Explain technical concepts in simple language.
6. If a scan is HIGH RISK, explain why and recommend
   safe defensive actions.
7. Never claim that a URL is malicious unless the
   provided scan data supports that conclusion.
8. Do not provide instructions for attacking systems,
   stealing credentials, bypassing security controls,
   or deploying malware.
9. Focus on defensive cybersecurity.

USER QUESTION:
{question}

USER'S RECENT SENTINEL SECURITY SCANS:
{security_context}

Now answer the user's question clearly and professionally.
If the question is about their scans, use the scan data above.
"""

                print("Sending request to Gemini...")

                # --------------------------------------
                # GEMINI
                # --------------------------------------

                response = gemini_client.models.generate_content(

                    model="gemini-3.5-flash",

                    contents=prompt
                )

                answer = response.text

                print("Gemini response received.")

                print("==========================================")

            except Exception as e:

                print("==========================================")
                print("SENTINEL AI ERROR")
                print(type(e).__name__)
                print(str(e))
                print("==========================================")

                error = (
                    "Unable to process your request. "
                    "Please check the server terminal."
                )

    return render_template(
        "ai_assistant.html",
        answer=answer,
        error=error,
        question=question
    )
# ==========================================
# SCAN HISTORY
# ==========================================

@app.route("/scan-history")
def scan_history():

    if "user_id" not in session:

        return redirect(
            url_for("login")
        )

    scans = URLScan.query.filter_by(

        user_id=session[
            "user_id"
        ]

    ).order_by(

        URLScan.created_at.desc()

    ).all()

    return render_template(

        "scan_history.html",

        scans=scans
    )


# ==========================================
# CREATE DATABASE TABLES
# ==========================================

with app.app_context():

    db.create_all()


# ==========================================
# RUN APPLICATION
# ==========================================

if __name__ == "__main__":

    app.run(
        debug=True
    )