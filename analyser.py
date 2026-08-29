"""
Phishing Email Identifier
--------------------------
Analyses emails for common phishing red flags and generates a short
report.  Includes 5 realistic sample emails with suspicious signs
highlighted.
"""

from __future__ import annotations

import re
import sys
import io
import textwrap
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Tuple

# Fix encoding on Windows consoles
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

# ---- Red-flag checklist -------------------------------------------

CHECKLIST: List[Tuple[str, str]] = [
    ("Urgent / threatening language",
     "Words like 'immediately', 'account suspended', 'act now', 'within 24 hours'"),
    ("Mismatched / shortened URLs",
     "Links that don't match the display text or use bit.ly/tinyurl obfuscation"),
    ("Unknown or spoofed sender",
     "Address doesn't match the supposed organisation (e.g. support@paypa1.com)"),
    ("Requests for sensitive data",
     "Asks for passwords, credit-card numbers, SSNs, or login credentials"),
    ("Generic greeting",
     "Dear Customer / Dear User instead of your real name"),
    ("Spelling & grammar errors",
     "Professional organisations rarely send emails full of typos"),
    ("Unexpected attachments",
     ".exe, .zip, .scr or macro-enabled Office files"),
    ("Too-good-to-be-true offers",
     "You've won a prize you never entered for"),
    ("Mismatched display name vs address",
     "Display says 'Bank of America' but address is random@gmail.com"),
    ("Suspicious reply-to address",
     "Reply-To differs from the From address"),
]

# ---- Sample emails ------------------------------------------------

@dataclass
class SampleEmail:
    sender: str
    reply_to: str
    subject: str
    body: str
    red_flags: List[str] = field(default_factory=list)

SAMPLE_EMAILS: List[SampleEmail] = [
    SampleEmail(
        sender="security@paypa1-verify.com",
        reply_to="helpdesk02@gmail.com",
        subject="URGENT: Your PayPal account has been limited!",
        body=(
            "Dear Customer,\n\n"
            "We have detected unusual sign-in activity on your account. "
            "Your account has been LIMITED until you verify your identity.\n\n"
            "Click the link below within 24 hours or your account will be "
            "permanently suspended:\n\n"
            "  http://bit.ly/3xP9kLm\n\n"
            "You must confirm your full name, date of birth, credit card "
            "number and PIN to restore access.\n\n"
            "Thank you,\nPayPal Security Team"
        ),
        red_flags=[
            "Unknown/spoofed sender (paypa1-verify.com, not paypal.com)",
            "Mismatched reply-to (Gmail instead of PayPal domain)",
            "Urgent/threatening language ('URGENT', 'permanently suspended')",
            "Shortened link hides real destination",
            "Requests sensitive data (credit card number, PIN)",
            "Generic greeting ('Dear Customer')",
        ],
    ),
    SampleEmail(
        sender="hr-department@microsoft-careers.net",
        reply_to="recruitment-hr@outlook.com",
        subject="Congratulations! You have been selected for a job interview",
        body=(
            "Dear Applicant,\n\n"
            "After reviewing your profile on LinkedIn, we are pleased to "
            "inform you that you have been shortlisted for the position of "
            "Senior Software Engineer at Microsoft.\n\n"
            "To confirm your interest, please reply with:\n"
            "  - Full legal name\n"
            "  - Home address\n"
            "  - Copy of your government-issued ID\n\n"
            "Kindly respond within 48 hours to secure your slot.\n\n"
            "Best regards,\nHR Department"
        ),
        red_flags=[
            "Unknown/spoofed sender domain (microsoft-careers.net)",
            "Mismatched reply-to address",
            "Requests government-issued ID (identity theft risk)",
            "Artificial urgency ('within 48 hours')",
            "Generic greeting ('Dear Applicant')",
        ],
    ),
    SampleEmail(
        sender="no-reply@arnazon-orders.com",
        reply_to="cs-service@amazon-service.co",
        subject="Your Amazon order #112-4873928-119203 could not be delivered",
        body=(
            "Hello,\n\n"
            "We were unable to deliver your recent order because the "
            "shipping address could not be verified.\n\n"
            "Please review and update your address by visiting:\n"
            "  https://arnazon.com/update-address\n\n"
            "If no action is taken within 12 hours, your order will be "
            "cancelled and your payment will not be refunded.\n\n"
            "Regards,\nAmazon Customer Service"
        ),
        red_flags=[
            "Mismatched link (arnazon.com vs amazon.com -- look-alike domain)",
            "Sender domain 'arnazon-orders.com' is not amazon.com",
            "Urgency + threat of losing money",
            "Mismatched reply-to address",
        ],
    ),
    SampleEmail(
        sender="prizes@winner-lottery-intl.org",
        reply_to="claim.prize@gmail.com",
        subject="YOU HAVE WON $5,000,000!!!",
        body=(
            "Dear Lucky Winner,\n\n"
            "Congratulations!!! You have been selected as the grand prize "
            "winner of the International Email Lottery conducted on "
            "August 25, 2026.\n\n"
            "Your winning ticket number is: TK-88210\n"
            "Prize amount: FIVE MILLION US DOLLARS ($5,000,000.00)\n\n"
            "To claim your prize, please provide:\n"
            "  1. Your full name and address\n"
            "  2. Bank account details for the transfer\n"
            "  3. A processing fee of $200 via gift cards\n\n"
            "Respond immediately!!!\n\n"
            "Dr. James Williams\nLottery Co-ordinator"
        ),
        red_flags=[
            "Too-good-to-be-true offer (you never entered a lottery)",
            "Unknown sender domain",
            "Requests bank account details",
            "Asks for upfront payment ($200 gift cards)",
            "Excessive exclamation marks and ALL CAPS",
            "Generic greeting ('Dear Lucky Winner')",
        ],
    ),
    SampleEmail(
        sender="IT-Support@yourcompany.com",
        reply_to="IT-Support@yourcompany.com",
        subject="Password expires today -- reset now",
        body=(
            "Hi John,\n\n"
            "This is a reminder that your network password expires today. "
            "Please click the link below to set a new password before "
            "end of business:\n\n"
            "  https://yourcompany.com/itsupport/password-reset\n\n"
            "Note: This link expires at 5 PM today. If you have any "
            "questions contact the IT Help Desk at ext. 4523.\n\n"
            "Thanks,\nIT Support Team"
        ),
        red_flags=[
            "Uses the user's real name and a convincing domain (potential spear-phishing)",
            "Urgent deadline (expires today, link expires at 5 PM)",
            "Requests action via link -- always verify the URL before clicking",
        ],
    ),
]

# ---- Analysis engine ----------------------------------------------

URGENCY_RE = re.compile(
    r"\b(immediately|urgent|act now|suspended|limited|within \d+ hours?|"
    r"expires today|permanently|before end of|don'?t delay|last chance|"
    r"respond immediately|secure your|no action|cancelled|not be refunded)\b",
    re.IGNORECASE,
)

SENSITIVE_RE = re.compile(
    r"\b(password|credit.card|pin|ssn|social security|bank account|"
    r"government.issued id|date of birth|full name|address|credentials|"
    r"login details|tax file|passport)\b",
    re.IGNORECASE,
)

SHORTENER_RE = re.compile(
    r"(bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|buff\.ly|ow\.ly)",
    re.IGNORECASE,
)

SPAMMY_RE = re.compile(
    r"(congratulations|you have been selected|lucky winner|prize|lottery|"
    r"million us dollars|you won|claim your|processing fee)",
    re.IGNORECASE,
)


@dataclass
class AnalysisResult:
    email: SampleEmail
    score: int
    flags_found: List[str] = field(default_factory=list)
    flags_expected: List[str] = field(default_factory=list)


def analyse_email(email: SampleEmail) -> AnalysisResult:
    """Score an email for phishing risk and list detected flags."""
    text = f"{email.sender} {email.reply_to} {email.subject} {email.body}"
    flags: List[str] = []
    score = 0

    if URGENCY_RE.search(text):
        flags.append("Urgent / threatening language")
        score += 18

    if SENSITIVE_RE.search(text):
        flags.append("Requests sensitive data")
        score += 20

    if SHORTENER_RE.search(email.body):
        flags.append("Shortened / obfuscated links")
        score += 12

    link_re = re.compile(r"https?://([^\s]+)")
    hrefs = link_re.findall(email.body)
    for href in hrefs:
        domain = href.split("/")[0]
        if any(c.isdigit() for c in domain.split(".")[0]) and domain not in ("bit.ly",):
            flags.append(f"Mismatched / look-alike domain in link ({domain})")
            score += 18
            break

    sender_domain = email.sender.split("@")[-1] if "@" in email.sender else ""
    known_domains = {"paypal.com", "microsoft.com", "amazon.com", "google.com",
                     "yourcompany.com"}
    if sender_domain and not any(kd in sender_domain for kd in known_domains):
        flags.append(f"Unknown sender domain ({sender_domain})")
        score += 12

    rt_domain = email.reply_to.split("@")[-1] if "@" in email.reply_to else ""
    if rt_domain != sender_domain:
        flags.append("Reply-To differs from sender domain")
        score += 8

    if re.search(r"\b(Dear (Customer|User|Applicant|Lucky Winner|Sir|Madam))\b",
                 email.body, re.I):
        flags.append("Generic greeting")
        score += 6

    if SPAMMY_RE.search(email.body):
        flags.append("Too-good-to-be-true claims / spammy language")
        score += 10

    score = min(score, 100)

    return AnalysisResult(
        email=email,
        score=score,
        flags_found=flags,
        flags_expected=email.red_flags,
    )

# ---- Report generation -------------------------------------------

DIVIDER = "=" * 64

def risk_label(score: int) -> str:
    if score >= 70:
        return "[!!!] HIGH"
    if score >= 40:
        return "[!!]  MEDIUM"
    if score >= 15:
        return "[!]   LOW"
    return "[OK]  SAFE"


def format_email_block(email: SampleEmail) -> str:
    return textwrap.dedent(f"""\
        From:    {email.sender}
        Reply-To:{email.reply_to}
        Subject: {email.subject}

        {email.body}
    """)


def generate_report(results: List[AnalysisResult]) -> str:
    lines: List[str] = []

    lines.append(DIVIDER)
    lines.append("       PHISHING EMAIL IDENTIFIER -- ANALYSIS REPORT")
    lines.append(f"       Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(DIVIDER)

    # Checklist
    lines.append("")
    lines.append("[CHECKLIST]  PHISHING RED-FLAG CHECKLIST")
    lines.append("")
    for i, (flag, desc) in enumerate(CHECKLIST, 1):
        lines.append(f"  {i:2d}. {flag}")
        lines.append(f"      {desc}")
    lines.append("")

    # Email analyses
    for idx, r in enumerate(results, 1):
        lines.append(DIVIDER)
        lines.append("")
        lines.append(f"[EMAIL {idx}/{len(results)}]  Risk: {risk_label(r.score)} ({r.score}/100)")
        lines.append("")
        lines.append(format_email_block(r.email))

        lines.append("  Detected red flags:")
        if r.flags_found:
            for f in r.flags_found:
                lines.append(f"    X {f}")
        else:
            lines.append("    (none detected)")

        missed = [e for e in r.flags_expected
                  if not any(e.lower() in f.lower() for f in r.flags_found)]
        if missed:
            lines.append("")
            lines.append("  Additional flags noted by human review:")
            for f in missed:
                lines.append(f"    ! {f}")
        lines.append("")

    # Summary
    lines.append(DIVIDER)
    lines.append("")
    lines.append("[SUMMARY]")
    lines.append("")
    lines.append(f"  {'Email':<6} {'Risk':<12} {'Score':<8} {'Subject'}")
    lines.append(f"  {'-'*5}  {'-'*11} {'-'*7}  {'-'*30}")
    for idx, r in enumerate(results, 1):
        label = risk_label(r.score)
        lines.append(f"  {idx:<6} {label:<12} {r.score:<8} {r.email.subject[:40]}")
    lines.append("")

    # Key takeaways
    lines.append(DIVIDER)
    lines.append("")
    lines.append("[KEY TAKEAWAYS]")
    lines.append("")
    lines.append("  * Never click links in suspicious emails -- hover to preview the URL first.")
    lines.append("  * Check the sender's actual email address, not just the display name.")
    lines.append("  * Legitimate organisations will never ask for passwords or PINs via email.")
    lines.append("  * If something feels urgent or too good to be true, verify independently.")
    lines.append("  * Report phishing emails to your IT department or reportphishing@apwg.org.")
    lines.append("")
    lines.append(DIVIDER)

    return "\n".join(lines)

# ---- Main --------------------------------------------------------

def main() -> None:
    results = [analyse_email(email) for email in SAMPLE_EMAILS]
    report = generate_report(results)
    print(report)

    report_path = "phishing_report.txt"
    with open(report_path, "w", encoding="utf-8") as fh:
        fh.write(report)
    print(f"\nReport saved to {report_path}")


if __name__ == "__main__":
    main()