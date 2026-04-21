"""
Password Security Analyzer — Enhanced
======================================
Flask backend: entropy, strength, pattern detection, real-world attack
estimation, 0-100 scoring, Have I Been Pwned k-anonymity integration.

Routes:
    GET  /           → Renders the main UI
    POST /analyze    → Accepts JSON {password}, returns analysis JSON
    GET  /health     → Health-check endpoint for Render / load balancers

Security guarantees:
    • Passwords are NEVER logged, stored, or echoed in any response
    • Only the first 5 hex chars of the SHA-1 hash are sent to HIBP
    • Input validated and capped at 128 characters

Run locally:
    pip install flask requests
    python app.py

Production (Render / gunicorn):
    gunicorn app:app
"""

import hashlib
import math
import os
import re
import string

import requests
from flask import Flask, jsonify, render_template, request

# ---------------------------------------------------------------------------
# App configuration
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-secret-change-in-prod")

HIBP_URL     = "https://api.pwnedpasswords.com/range/{prefix}"
HIBP_AGENT   = "PasswordSecurityAnalyzer/2.0"
HIBP_TIMEOUT = 6   # seconds

# Crack-speed constants
GPU_GUESSES_PER_SEC  = 1_000_000_000_000   # 10^12 — modern GPU cluster (brute force)
DICT_GUESSES_PER_SEC = 1_000_000_000        # 10^9  — dictionary/rule-based attacks

# ─── Common-password wordlist (top hits used in red-team tool sets) ─────────
COMMON_PASSWORDS = {
    "password", "password1", "password123", "123456", "12345678",
    "1234567890", "qwerty", "qwerty123", "qwertyuiop", "abc123",
    "letmein", "monkey", "dragon", "master", "welcome",
    "admin", "admin123", "root", "toor", "pass",
    "login", "test", "guest", "user", "iloveyou",
    "trustno1", "sunshine", "princess", "shadow", "superman",
    "batman", "football", "baseball", "soccer", "hockey",
    "123123", "654321", "111111", "000000", "121212",
    "696969", "1q2w3e", "zaq1zaq1", "starwars", "hello",
    "mustang", "michael", "jessica", "access", "ninja",
    "thomas", "hunter", "ranger", "killer", "jordan",
    "harley", "ranger", "buster", "tigger", "robert",
    "joseph", "daniel", "andrew", "george", "charlie",
}

# Common keyboard-walk sequences
_KEYBOARD_WALKS = [
    "qwerty", "qwertyuiop", "asdfgh", "asdfghjkl", "zxcvbn",
    "1qaz", "2wsx", "3edc", "4rfv", "5tgb", "6yhn", "7ujm",
    "qazwsx", "wsxedc", "1234qwer", "qweasdzxc",
]

# Sequences to detect
_SEQ_DIGITS  = "0123456789"
_SEQ_ALPHA_L = "abcdefghijklmnopqrstuvwxyz"
_SEQ_ALPHA_U = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


# ---------------------------------------------------------------------------
# 1. Entropy & charset helpers  (unchanged API from v1)
# ---------------------------------------------------------------------------

def _charset_size(password: str) -> int:
    size = 0
    if any(c in string.ascii_lowercase for c in password):
        size += 26
    if any(c in string.ascii_uppercase for c in password):
        size += 26
    if any(c.isdigit() for c in password):
        size += 10
    if any(c in set(string.punctuation) for c in password):
        size += 32
    if any(ord(c) > 127 for c in password):
        size += 64
    return max(size, 1)


def calculate_entropy(password: str) -> float:
    """log2(charset) × length — worst-case brute-force search space in bits."""
    return math.log2(_charset_size(password)) * len(password)


def _charset_breakdown(password: str) -> list[dict]:
    bd = []
    if any(c in string.ascii_lowercase for c in password):
        bd.append({"label": "Lowercase letters", "size": 26, "icon": "🔡"})
    if any(c in string.ascii_uppercase for c in password):
        bd.append({"label": "Uppercase letters", "size": 26, "icon": "🔠"})
    if any(c.isdigit() for c in password):
        bd.append({"label": "Digits (0–9)", "size": 10, "icon": "🔢"})
    if any(c in set(string.punctuation) for c in password):
        bd.append({"label": "Special symbols", "size": 32, "icon": "✳️"})
    if any(ord(c) > 127 for c in password):
        bd.append({"label": "Unicode / extended chars", "size": 64, "icon": "🌐"})
    return bd


# ---------------------------------------------------------------------------
# 2. Pattern detection  (NEW)
# ---------------------------------------------------------------------------

def detect_patterns(password: str) -> list[dict]:
    """
    Detect real-world weak patterns in a password.
    Returns a list of warning dicts: {code, severity, message}.
    Severity: 'critical' | 'high' | 'medium'
    """
    warnings = []
    low = password.lower()

    # ── Common password exact match ────────────────────────────────────────
    if low in COMMON_PASSWORDS:
        warnings.append({
            "code":     "COMMON_PASSWORD",
            "severity": "critical",
            "message":  "This is one of the most commonly used passwords and will be tried first by any attacker.",
        })

    # ── Keyboard walk ──────────────────────────────────────────────────────
    for walk in _KEYBOARD_WALKS:
        if walk in low:
            warnings.append({
                "code":     "KEYBOARD_WALK",
                "severity": "high",
                "message":  f'Contains keyboard walk sequence ("{walk}") — easily guessed by rule-based attacks.',
            })
            break

    # ── Sequential digits (e.g. 123, 234, 9876) ───────────────────────────
    _found_seq_digit = False
    for i in range(len(password) - 2):
        chunk = password[i:i+3]
        pos_asc  = _SEQ_DIGITS.find(chunk)
        pos_desc = _SEQ_DIGITS.find(chunk[::-1])
        if (pos_asc != -1) or (pos_desc != -1):
            _found_seq_digit = True
            break
    if _found_seq_digit:
        warnings.append({
            "code":     "SEQUENTIAL_DIGITS",
            "severity": "high",
            "message":  "Contains sequential digit runs (e.g. 123, 456, 987) — a common mutation cracking tools try.",
        })

    # ── Sequential alpha (e.g. abc, xyz) ──────────────────────────────────
    _found_seq_alpha = False
    for i in range(len(low) - 2):
        chunk = low[i:i+3]
        if (_SEQ_ALPHA_L.find(chunk) != -1) or (_SEQ_ALPHA_L.find(chunk[::-1]) != -1):
            _found_seq_alpha = True
            break
    if _found_seq_alpha:
        warnings.append({
            "code":     "SEQUENTIAL_ALPHA",
            "severity": "medium",
            "message":  "Contains sequential letter runs (e.g. abc, xyz) — reduces effective entropy.",
        })

    # ── Repeated characters (aaa, 111, ...) ───────────────────────────────
    if re.search(r'(.)\1{2,}', password):
        warnings.append({
            "code":     "REPEATED_CHARS",
            "severity": "high",
            "message":  "Contains 3+ repeated characters in a row (e.g. aaa, 111) — dramatically weakens entropy.",
        })

    # ── Only digits ────────────────────────────────────────────────────────
    if password.isdigit():
        warnings.append({
            "code":     "DIGITS_ONLY",
            "severity": "critical",
            "message":  "Password is entirely numeric — trivially cracked by digit-only brute force.",
        })

    # ── Only letters ──────────────────────────────────────────────────────
    if password.isalpha():
        warnings.append({
            "code":     "ALPHA_ONLY",
            "severity": "medium",
            "message":  "Password contains only letters — add digits and symbols for stronger resistance.",
        })

    # ── Starts/ends with common suffixes (1, 123, !, 1234) ───────────────
    if re.search(r'^(password|pass|admin|user|login|welcome|hello)', low):
        warnings.append({
            "code":     "COMMON_PREFIX",
            "severity": "critical",
            "message":  "Starts with a very common word (password, admin, hello…) — rule-based tools mutate these first.",
        })

    if re.search(r'(123|1234|12345|!\s*$|@\s*$|1\s*$)$', password):
        warnings.append({
            "code":     "COMMON_SUFFIX",
            "severity": "high",
            "message":  "Ends with a predictable suffix (123, 1234, !, @, 1) — a common pattern tools exploit.",
        })

    # ── Short password ────────────────────────────────────────────────────
    if len(password) < 8:
        warnings.append({
            "code":     "TOO_SHORT",
            "severity": "critical",
            "message":  f"Only {len(password)} characters — minimum recommended length is 12.",
        })
    elif len(password) < 12:
        warnings.append({
            "code":     "COULD_BE_LONGER",
            "severity": "medium",
            "message":  f"{len(password)} characters is acceptable but 12+ is recommended for better protection.",
        })

    return warnings


# ---------------------------------------------------------------------------
# 3. Real-world attack estimation  (NEW)
# ---------------------------------------------------------------------------

# Dictionary-attack effective space depending on detected patterns
_DICT_SIZES = {
    "COMMON_PASSWORD": 10_000,          # top-10 k password list
    "KEYBOARD_WALK":   500_000,          # keyboard permutations
    "SEQUENTIAL_DIGITS": 1_000_000,      # digit combos
    "SEQUENTIAL_ALPHA":  5_000_000,
    "REPEATED_CHARS":    1_000_000,
    "DIGITS_ONLY":       10 ** len("000"),   # will be overridden per-call
    "ALPHA_ONLY":        26 ** 6,
    "COMMON_PREFIX":     2_000_000,
    "COMMON_SUFFIX":     2_000_000,
}

def _seconds_to_human(seconds: float) -> str:
    """Convert a seconds value to human-readable crack time string."""
    try:
        if seconds < 0.001:
            return "Instantly (< 1 ms)"
        if seconds < 1:
            return f"~{seconds*1000:.0f} milliseconds"
        if seconds < 60:
            s = int(seconds)
            return f"~{s} second{'s' if s != 1 else ''}"
        if seconds < 3_600:
            m = int(seconds / 60)
            return f"~{m} minute{'s' if m != 1 else ''}"
        if seconds < 86_400:
            h = int(seconds / 3_600)
            return f"~{h} hour{'s' if h != 1 else ''}"
        if seconds < 31_536_000:
            d = int(seconds / 86_400)
            return f"~{d:,} day{'s' if d != 1 else ''}"
        if seconds < 31_536_000 * 1_000:
            y = int(seconds / 31_536_000)
            return f"~{y:,} year{'s' if y != 1 else ''}"
        if seconds < 31_536_000 * 1_000_000:
            return f"~{int(seconds/(31_536_000*1_000)):,} thousand years"
        if seconds < 31_536_000 * 1_000_000_000:
            return f"~{int(seconds/(31_536_000*1_000_000)):,} million years"
        return f"~{int(seconds/(31_536_000*1_000_000_000)):,} billion years"
    except OverflowError:
        return "Heat death of the universe (effectively uncrackable)"


def estimate_brute_force_time(entropy: float) -> str:
    """Worst-case brute force at 10¹² guesses/sec."""
    try:
        seconds = (2 ** entropy) / GPU_GUESSES_PER_SEC
        return _seconds_to_human(seconds)
    except OverflowError:
        return "Heat death of the universe (effectively uncrackable)"


def estimate_realworld_time(password: str, pattern_warnings: list[dict]) -> str:
    """
    Practical dictionary/rule-based attack estimate.
    If patterns are detected, reduce the effective search space dramatically.
    Falls back to brute-force estimate if no patterns found.
    """
    pw_len = len(password)
    low    = password.lower()

    # ── Exact common password ─────────────────────────────────────────────
    if low in COMMON_PASSWORDS:
        return _seconds_to_human(10_000 / DICT_GUESSES_PER_SEC)

    codes = {w["code"] for w in pattern_warnings}

    # ── Build effective dict space from patterns ──────────────────────────
    if "DIGITS_ONLY" in codes:
        space = 10 ** pw_len
        return _seconds_to_human(space / DICT_GUESSES_PER_SEC)

    if "KEYBOARD_WALK" in codes or "COMMON_PREFIX" in codes:
        # Rule-based tools try these with mutations → small effective space
        space = 500_000 * max(pw_len, 1)
        return _seconds_to_human(space / DICT_GUESSES_PER_SEC)

    if "SEQUENTIAL_DIGITS" in codes or "COMMON_SUFFIX" in codes:
        space = 5_000_000 * max(pw_len, 1)
        return _seconds_to_human(space / DICT_GUESSES_PER_SEC)

    if "REPEATED_CHARS" in codes or "SEQUENTIAL_ALPHA" in codes:
        space = 20_000_000 * max(pw_len, 1)
        return _seconds_to_human(space / DICT_GUESSES_PER_SEC)

    if "ALPHA_ONLY" in codes:
        # Wordlist + mangling rules
        space = (26 ** pw_len) / 10  # effective reduction due to wordlists
        return _seconds_to_human(max(space, 1) / DICT_GUESSES_PER_SEC)

    # No significant patterns — real-world ≈ brute force (but use 10^9 speed)
    entropy = calculate_entropy(password)
    try:
        seconds = (2 ** entropy) / DICT_GUESSES_PER_SEC
        return _seconds_to_human(seconds)
    except OverflowError:
        return "Heat death of the universe (effectively uncrackable)"


# ---------------------------------------------------------------------------
# 4. Password Score 0–100  (NEW)
# ---------------------------------------------------------------------------

def calculate_score(
    password: str,
    entropy: float,
    pattern_warnings: list[dict],
    hibp: dict,
) -> dict:
    """
    Score breakdown (total 100 pts):
        Length diversity  — up to 30 pts
        Char diversity    — up to 30 pts
        Entropy strength  — up to 20 pts
        Breach safety     — up to 20 pts

    Returns {total, breakdown, explanation, grade}
    """
    pw_len  = len(password)
    codes   = {w["code"] for w in pattern_warnings}
    has_critical = any(w["severity"] == "critical" for w in pattern_warnings)

    explanation = []   # list of {icon, text, positive}

    # ── A. Length (30 pts) ────────────────────────────────────────────────
    if pw_len >= 20:
        length_pts = 30
        explanation.append({"icon": "✔", "text": f"Excellent length ({pw_len} characters)", "positive": True})
    elif pw_len >= 16:
        length_pts = 24
        explanation.append({"icon": "✔", "text": f"Good length ({pw_len} characters)", "positive": True})
    elif pw_len >= 12:
        length_pts = 18
        explanation.append({"icon": "✔", "text": f"Acceptable length ({pw_len} characters; 16+ preferred)", "positive": True})
    elif pw_len >= 8:
        length_pts = 10
        explanation.append({"icon": "⚠", "text": f"Short password ({pw_len} chars) — aim for 12+", "positive": False})
    else:
        length_pts = 3
        explanation.append({"icon": "✖", "text": f"Very short ({pw_len} chars) — highly vulnerable", "positive": False})

    # ── B. Character diversity (30 pts) ───────────────────────────────────
    has_lower   = any(c in string.ascii_lowercase for c in password)
    has_upper   = any(c in string.ascii_uppercase for c in password)
    has_digit   = any(c.isdigit() for c in password)
    has_symbol  = any(c in set(string.punctuation) for c in password)
    has_unicode = any(ord(c) > 127 for c in password)

    types_count = sum([has_lower, has_upper, has_digit, has_symbol, has_unicode])
    diversity_pts = min(types_count * 7, 30)   # 7 pts per type, cap at 30

    if has_symbol:
        explanation.append({"icon": "✔", "text": "Uses special symbols", "positive": True})
    else:
        explanation.append({"icon": "⚠", "text": "No special symbols — adding them greatly increases strength", "positive": False})
    if has_upper and has_lower:
        explanation.append({"icon": "✔", "text": "Mixes uppercase and lowercase", "positive": True})
    elif not has_upper:
        explanation.append({"icon": "⚠", "text": "No uppercase letters detected", "positive": False})
    if has_digit:
        explanation.append({"icon": "✔", "text": "Contains digits", "positive": True})

    # ── C. Entropy strength (20 pts) ──────────────────────────────────────
    if entropy >= 80:
        entropy_pts = 20
        explanation.append({"icon": "✔", "text": f"High entropy ({entropy:.1f} bits) — excellent randomness", "positive": True})
    elif entropy >= 56:
        entropy_pts = 16
        explanation.append({"icon": "✔", "text": f"Solid entropy ({entropy:.1f} bits)", "positive": True})
    elif entropy >= 36:
        entropy_pts = 10
        explanation.append({"icon": "⚠", "text": f"Moderate entropy ({entropy:.1f} bits) — aim for 60+ bits", "positive": False})
    else:
        entropy_pts = 4
        explanation.append({"icon": "✖", "text": f"Low entropy ({entropy:.1f} bits) — very guessable", "positive": False})

    # Pattern penalty on entropy component
    if "COMMON_PASSWORD" in codes or "KEYBOARD_WALK" in codes:
        entropy_pts = max(entropy_pts - 10, 0)
        explanation.append({"icon": "✖", "text": "Predictable pattern drastically reduces effective entropy", "positive": False})
    elif "SEQUENTIAL_DIGITS" in codes or "REPEATED_CHARS" in codes:
        entropy_pts = max(entropy_pts - 5, 0)
        explanation.append({"icon": "⚠", "text": "Repeating/sequential pattern lowers effective entropy", "positive": False})

    # ── D. Breach safety (20 pts) ─────────────────────────────────────────
    if hibp.get("error"):
        breach_pts = 10   # neutral — can't verify
        explanation.append({"icon": "⚡", "text": "Breach check unavailable (API error)", "positive": False})
    elif hibp.get("found"):
        breach_pts = 0
        count = hibp.get("count", 0)
        explanation.append({"icon": "✖", "text": f"Found in {count:,} known data breaches — do not use", "positive": False})
    else:
        breach_pts = 20
        explanation.append({"icon": "✔", "text": "Not found in any known breach database (HIBP)", "positive": True})

    # ── Critical pattern hard-cap ──────────────────────────────────────────
    raw_total = length_pts + diversity_pts + entropy_pts + breach_pts
    if has_critical:
        raw_total = min(raw_total, 35)   # cap at 35 if any critical pattern present

    total = min(max(raw_total, 0), 100)

    # ── Grade ──────────────────────────────────────────────────────────────
    if total >= 80:
        grade, grade_class = "A", "grade-a"
    elif total >= 65:
        grade, grade_class = "B", "grade-b"
    elif total >= 45:
        grade, grade_class = "C", "grade-c"
    elif total >= 25:
        grade, grade_class = "D", "grade-d"
    else:
        grade, grade_class = "F", "grade-f"

    return {
        "total":      total,
        "grade":      grade,
        "grade_class": grade_class,
        "breakdown": {
            "length":    {"pts": length_pts,    "max": 30, "label": "Password Length"},
            "diversity": {"pts": diversity_pts, "max": 30, "label": "Character Diversity"},
            "entropy":   {"pts": entropy_pts,   "max": 20, "label": "Entropy Strength"},
            "breach":    {"pts": breach_pts,    "max": 20, "label": "Breach Safety"},
        },
        "explanation": explanation,
    }


# ---------------------------------------------------------------------------
# 5. Strength classification  (updated to respect pattern warnings)
# ---------------------------------------------------------------------------

def classify_strength(entropy: float, pattern_warnings: list[dict] | None = None) -> dict:
    """
    Classify password strength.  If critical patterns are found, downgrade
    to 'weak' regardless of entropy.
    """
    codes        = {w["code"] for w in (pattern_warnings or [])}
    has_critical = any(w["severity"] == "critical" for w in (pattern_warnings or []))

    # Common-password override
    if has_critical or "COMMON_PASSWORD" in codes:
        return {
            "key":     "weak",
            "class":   "low",
            "label":   "Weak",
            "message": "Despite apparent complexity, this password is trivially cracked due to known patterns.",
            "tips": [
                "🔑 Use a passphrase of 4+ random words (e.g. 'coral-anvil-sunset-42').",
                "🔡 Avoid known words, names, or keyboard sequences entirely.",
                "🗂️ Generate passwords with a trusted password manager.",
            ],
        }

    if entropy < 28:
        return {
            "key": "weak", "class": "low", "label": "Weak",
            "message": "This password can be cracked almost instantly by brute force.",
            "tips": ["🔑 Use at least 12 characters.", "🔡 Mix all character types.", "🚫 Avoid dictionary words."],
        }
    if entropy < 56:
        return {
            "key": "medium", "class": "medium", "label": "Medium",
            "message": "Moderate protection — a determined attacker could still crack it.",
            "tips": [
                "📏 Consider a longer password (16+ characters).",
                "🔀 Add more symbol variety for higher entropy.",
                "🗂️ Use a password manager to generate truly random passwords.",
            ],
        }
    return {
        "key": "strong", "class": "high", "label": "Strong",
        "message": "Excellent — this password offers strong brute-force resistance.",
        "tips": [
            "✅ Excellent entropy! Keep using unique passwords per service.",
            "🛡️ Pair with Two-Factor Authentication for maximum protection.",
            "🔄 Rotate passwords periodically for high-value accounts.",
        ],
    }


# ---------------------------------------------------------------------------
# 6. Have I Been Pwned — k-anonymity  (unchanged from v1)
# ---------------------------------------------------------------------------

def check_hibp(password: str) -> dict:
    sha1   = hashlib.sha1(password.encode("utf-8"), usedforsecurity=False).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        resp = requests.get(
            HIBP_URL.format(prefix=prefix),
            headers={"User-Agent": HIBP_AGENT, "Add-Padding": "true"},
            timeout=HIBP_TIMEOUT,
        )
        resp.raise_for_status()
    except requests.exceptions.Timeout:
        return {"found": False, "count": 0, "error": "HIBP API timed out — try again later."}
    except requests.exceptions.ConnectionError:
        return {"found": False, "count": 0, "error": "Could not connect to HIBP API — check internet access."}
    except requests.exceptions.HTTPError as exc:
        return {"found": False, "count": 0, "error": f"HIBP API returned HTTP {exc.response.status_code}."}
    except Exception as exc:
        return {"found": False, "count": 0, "error": f"Unexpected error: {exc}"}

    for line in resp.text.splitlines():
        parts = line.split(":")
        if len(parts) == 2 and parts[0].strip() == suffix:
            return {"found": True, "count": int(parts[1].strip()), "error": None}
    return {"found": False, "count": 0, "error": None}


# ---------------------------------------------------------------------------
# 7. Master orchestration  (updated return schema)
# ---------------------------------------------------------------------------

def analyze_password(password: str) -> dict:
    """
    Run all analyses.  The raw password NEVER appears in the returned dict.
    """
    entropy          = calculate_entropy(password)
    pattern_warnings = detect_patterns(password)
    strength         = classify_strength(entropy, pattern_warnings)
    brute_force_time = estimate_brute_force_time(entropy)
    realworld_time   = estimate_realworld_time(password, pattern_warnings)
    hibp             = check_hibp(password)
    score            = calculate_score(password, entropy, pattern_warnings, hibp)
    charset_bd       = _charset_breakdown(password)

    has_patterns = len(pattern_warnings) > 0
    has_critical = any(w["severity"] == "critical" for w in pattern_warnings)

    return {
        # ── Core metrics ────────────────────────────────────────────────
        "length":       len(password),
        "charset_size": _charset_size(password),
        "entropy":      round(entropy, 2),

        # ── Crack times ─────────────────────────────────────────────────
        "brute_force_crack_time": brute_force_time,
        "real_world_crack_time":  realworld_time,

        # ── Strength ────────────────────────────────────────────────────
        "strength": strength,

        # ── Pattern analysis ────────────────────────────────────────────
        "patterns": {
            "found":       has_patterns,
            "has_critical": has_critical,
            "warnings":    pattern_warnings,
            "count":       len(pattern_warnings),
        },

        # ── Score ───────────────────────────────────────────────────────
        "score": score,

        # ── HIBP breach ─────────────────────────────────────────────────
        "breach": {
            "found":   hibp["found"],
            "count":   hibp["count"],
            "error":   hibp["error"],
            "status_class": (
                "danger"  if hibp["found"]  else
                "warning" if hibp["error"]  else
                "safe"
            ),
            "status_label": (
                "⚠️ Pwned — Found in Breaches"              if hibp["found"] else
                "⚡ API Unavailable"                         if hibp["error"] else
                "✔ Not found in known breaches (HIBP database)"
            ),
        },

        # ── Detail table ────────────────────────────────────────────────
        "charset_breakdown": charset_bd,
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    """
    POST /analyze   body: {"password": "..."}
    Returns JSON analysis.  Raw password is NEVER stored, logged, or echoed.
    """
    body     = request.get_json(silent=True) or {}
    raw      = body.get("password", "")

    if not isinstance(raw, str):
        return jsonify({"error": "Invalid input."}), 400

    password = raw.strip()

    if not password:
        return jsonify({"error": "Password cannot be empty."}), 400
    if len(password) > 128:
        return jsonify({"error": "Password too long (max 128 characters)."}), 400

    return jsonify(analyze_password(password))


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "password-security-analyzer"})


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
