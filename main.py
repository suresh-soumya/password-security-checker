"""
Privacy Settings Risk Analyzer
================================
Collects three privacy settings from the user, calculates a risk score
(0-10), displays a colour-coded result with a visual bar, a detailed
breakdown, and actionable recommendations.

Dependencies (optional – gracefully degraded when absent):
    pip install colorama
"""

import io
import sys

# Force UTF-8 output so emoji display correctly on Windows terminals
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

# ---------------------------------------------------------------------------
# Optional dependency: colorama for Windows ANSI colour support
# ---------------------------------------------------------------------------
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    _COLOUR = True
except ImportError:
    _COLOUR = False

    class _DummyFore:
        """Fallback that returns empty strings so colour calls are no-ops."""
        def __getattr__(self, _):
            return ""

    class _DummyStyle:
        def __getattr__(self, _):
            return ""

    Fore = _DummyFore()
    Style = _DummyStyle()


# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------

def red(text: str) -> str:
    return f"{Fore.RED}{Style.BRIGHT}{text}{Style.RESET_ALL}"

def yellow(text: str) -> str:
    return f"{Fore.YELLOW}{Style.BRIGHT}{text}{Style.RESET_ALL}"

def green(text: str) -> str:
    return f"{Fore.GREEN}{Style.BRIGHT}{text}{Style.RESET_ALL}"

def cyan(text: str) -> str:
    return f"{Fore.CYAN}{text}{Style.RESET_ALL}"

def bold(text: str) -> str:
    return f"{Style.BRIGHT}{text}{Style.RESET_ALL}"

def dim(text: str) -> str:
    return f"{Style.DIM}{text}{Style.RESET_ALL}"


# ---------------------------------------------------------------------------
# Input helpers
# ---------------------------------------------------------------------------

def get_valid_input(prompt: str, valid_options: list[str]) -> str:
    """Re-prompt the user until a valid choice is entered (case-insensitive)."""
    option_str = " / ".join(valid_options)
    while True:
        raw = input(f"{cyan('→')} {prompt} {dim(f'[{option_str}]')}: ").strip().lower()
        if raw in valid_options:
            return raw
        print(f"  {yellow('⚠')}  Invalid input. Please choose one of: "
              f"{bold(option_str)}\n")


# ---------------------------------------------------------------------------
# Scoring logic
# ---------------------------------------------------------------------------

# Individual factor weights (max total = 10)
_PASSWORD_SCORES   = {"weak": 4, "medium": 2, "strong": 0}
_LOCATION_SCORES   = {"yes": 3, "no": 0}
_VISIBILITY_SCORES = {"public": 3, "private": 0}

MAX_SCORE = (
    max(_PASSWORD_SCORES.values())
    + max(_LOCATION_SCORES.values())
    + max(_VISIBILITY_SCORES.values())
)  # == 10


def calculate_risk_score(
    password_strength: str,
    location_sharing: str,
    profile_visibility: str,
) -> tuple[int, dict[str, int]]:
    """
    Return (total_score, breakdown) where breakdown maps each factor to its
    individual risk contribution.
    """
    breakdown = {
        "Password Strength":  _PASSWORD_SCORES[password_strength],
        "Location Sharing":   _LOCATION_SCORES[location_sharing],
        "Profile Visibility": _VISIBILITY_SCORES[profile_visibility],
    }
    return sum(breakdown.values()), breakdown


def risk_level(score: int) -> tuple[str, str, str]:
    """Return (label, emoji, one-line summary) based on the numeric score."""
    if score >= 7:
        return "HIGH",   "🔴", red("Immediate action required – your privacy is at risk!")
    elif score >= 4:
        return "MEDIUM", "🟡", yellow("Some improvements are advised.")
    else:
        return "LOW",    "🟢", green("Your privacy settings look solid. Keep it up!")


def build_recommendations(
    password_strength: str,
    location_sharing: str,
    profile_visibility: str,
) -> list[str]:
    """Return actionable recommendation strings for every risky setting."""
    tips = []

    if password_strength == "weak":
        tips.append(
            "🔑  Use a strong password: mix uppercase, lowercase, digits & symbols "
            "(12+ characters)."
        )
    elif password_strength == "medium":
        tips.append(
            "🔑  Upgrade your password strength – consider a passphrase or a password manager."
        )

    if location_sharing == "yes":
        tips.append(
            "📍  Disable location sharing to prevent apps from tracking your physical whereabouts."
        )

    if profile_visibility == "public":
        tips.append(
            "👤  Switch your profile to private so only approved connections can view it."
        )

    return tips


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def _score_bar(score: int, max_score: int, width: int = 30) -> str:
    """Return a visual progress bar string coloured by risk level."""
    filled = round(score / max_score * width)
    bar = "█" * filled + "░" * (width - filled)
    if score >= 7:
        return red(bar)
    elif score >= 4:
        return yellow(bar)
    else:
        return green(bar)


def _colour_factor_score(value: int, max_value: int) -> str:
    """Colour-code a single factor's score."""
    ratio = value / max_value if max_value else 0
    text = f"{value}/{max_value}"
    if ratio >= 0.75:
        return red(text)
    elif ratio >= 0.4:
        return yellow(text)
    else:
        return green(text)


FACTOR_MAXES = {
    "Password Strength":  max(_PASSWORD_SCORES.values()),
    "Location Sharing":   max(_LOCATION_SCORES.values()),
    "Profile Visibility": max(_VISIBILITY_SCORES.values()),
}


def display_results(
    password_strength: str,
    location_sharing: str,
    profile_visibility: str,
    score: int,
    breakdown: dict[str, int],
) -> None:
    level, emoji, summary = risk_level(score)
    tips = build_recommendations(password_strength, location_sharing, profile_visibility)

    W = 54  # banner width

    print()
    print(bold("=" * W))
    print()

    # Score bar
    bar = _score_bar(score, MAX_SCORE)
    print(f"  {bar}  {bold(f'{score}/{MAX_SCORE}')}")
    print()

    # Risk level banner
    print(f"  Risk Level : {emoji}  {bold(level)}")
    print(f"  Summary    : {summary}")
    print()

    # Detailed breakdown table
    print(bold("  ┌─ Score Breakdown " + "─" * (W - 21) + "┐"))
    print(bold(f"  │  {'Factor':<22} {'Your Choice':<14} {'Score':>6}  │"))
    print(bold("  ├" + "─" * (W - 4) + "┤"))

    rows = [
        ("Password Strength",  password_strength.capitalize()),
        ("Location Sharing",   location_sharing.capitalize()),
        ("Profile Visibility", profile_visibility.capitalize()),
    ]
    for factor, choice in rows:
        pts     = breakdown[factor]
        max_pts = FACTOR_MAXES[factor]
        pts_str = _colour_factor_score(pts, max_pts)
        print(f"  {bold('│')}  {factor:<22} {dim(choice):<14} {pts_str:>6}  {bold('│')}")

    print(bold("  ├" + "─" * (W - 4) + "┤"))
    total_str = _colour_factor_score(score, MAX_SCORE)
    print(f"  {bold('│')}  {'TOTAL':<22} {'':14} {total_str:>6}  {bold('│')}")
    print(bold("  └" + "─" * (W - 4) + "┘"))

    # Recommendations
    print()
    if tips:
        print(bold("  📋  Recommendations:"))
        for tip in tips:
            print(f"    {yellow('•')}  {tip}")
    else:
        print(green("  ✅  No immediate action needed – great privacy hygiene!"))

    print()
    print(bold("=" * W))


# ---------------------------------------------------------------------------
# Main flow
# ---------------------------------------------------------------------------

def analyze_privacy() -> None:
    W = 54
    print()
    print(bold("=" * W))
    title = "[*] Privacy Settings Risk Analyzer"
    print(bold(title.center(W)))
    print(bold("=" * W))
    print()
    print(dim("  Answer the questions below to receive your privacy risk score."))
    print(dim("  Scores range from 0 (safest) to 10 (highest risk).\n"))

    password_strength = get_valid_input(
        "Password strength",
        ["weak", "medium", "strong"],
    )
    location_sharing = get_valid_input(
        "Location sharing enabled?",
        ["yes", "no"],
    )
    profile_visibility = get_valid_input(
        "Profile visibility",
        ["public", "private"],
    )

    score, breakdown = calculate_risk_score(
        password_strength, location_sharing, profile_visibility
    )

    display_results(
        password_strength, location_sharing, profile_visibility,
        score, breakdown,
    )


def main() -> None:
    while True:
        analyze_privacy()
        print()
        again = get_valid_input("Run another analysis?", ["yes", "no"])
        if again == "no":
            print(f"\n  {green('👋  Stay safe out there!')}\n")
            sys.exit(0)
        print()


if __name__ == "__main__":
    main()