"""
Phishing URL Detector
A rule-based tool that analyzes URLs for common phishing characteristics.
"""

import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account",
    "update", "bank", "free", "password", "confirm",
    "signin", "credential", "suspend", "alert", "urgent",
]

TYPOSQUAT_PATTERNS = {
    "paypa1": "paypal",
    "micros0ft": "microsoft",
    "g00gle": "google",
    "amaz0n": "amazon",
    "faceb00k": "facebook",
    "app1e": "apple",
    "netf1ix": "netflix",
}


def check_suspicious_keywords(url):
    """Check for suspicious keywords commonly found in phishing URLs."""
    found = [word for word in SUSPICIOUS_KEYWORDS if word in url]
    if found:
        return 1, f"Contains suspicious keyword(s): {', '.join(found)}"
    return 0, None


def check_url_length(url):
    """Flag unusually long URLs."""
    if len(url) > 75:
        return 1, f"URL is unusually long ({len(url)} characters)"
    return 0, None


def check_at_symbol(url):
    """Check for '@' symbol used to obscure the real destination."""
    parsed = urlparse(url)
    path_and_rest = url.replace(f"{parsed.scheme}://", "", 1) if parsed.scheme else url
    if "@" in path_and_rest:
        return 1, "Contains '@' symbol (may redirect to a different host)"
    return 0, None


def check_ip_address(url):
    """Check if URL uses an IP address instead of a domain name."""
    if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url):
        return 2, "Uses IP address instead of domain name"
    return 0, None


def check_https(url):
    """Check if URL uses HTTPS."""
    if not url.startswith("https://"):
        return 1, "Does not use HTTPS"
    return 0, None


def check_typosquatting(url):
    """Check for known typosquatting patterns in the domain."""
    parsed = urlparse(url if "://" in url else f"http://{url}")
    domain = parsed.netloc.lower()
    found = []
    for typo, real in TYPOSQUAT_PATTERNS.items():
        if typo in domain:
            found.append(f"'{typo}' (looks like '{real}')")
    if found:
        return 1, f"Possible typosquatting detected: {', '.join(found)}"
    return 0, None


def check_subdomain_count(url):
    """Flag URLs with an excessive number of subdomains."""
    parsed = urlparse(url if "://" in url else f"http://{url}")
    domain = parsed.netloc
    dot_count = domain.count(".")
    if dot_count > 3:
        return 1, f"Too many subdomains ({dot_count} dots in domain)"
    return 0, None


def analyze_url(url):
    """
    Analyze a URL for phishing characteristics.

    Returns a tuple of (score, label, reasons).
    """
    url_lower = url.lower().strip()

    checks = [
        check_suspicious_keywords,
        check_url_length,
        check_at_symbol,
        check_ip_address,
        check_https,
        check_typosquatting,
        check_subdomain_count,
    ]

    total_score = 0
    reasons = []

    for check in checks:
        score, reason = check(url_lower)
        total_score += score
        if reason:
            reasons.append(reason)

    if total_score >= 5:
        label = "PHISHING"
    elif total_score >= 2:
        label = "SUSPICIOUS"
    else:
        label = "SAFE"

    return total_score, label, reasons


def display_result(url, score, label, reasons):
    """Display the analysis result."""
    icons = {"PHISHING": "\U0001f6a8", "SUSPICIOUS": "\u26a0\ufe0f", "SAFE": "\u2705"}

    print(f"\n\U0001f50d Analysis Result for: {url}")
    print(f"{icons.get(label, '')} {label} (score: {score})")

    if reasons:
        print("\nReasons:")
        for reason in reasons:
            print(f"  - {reason}")
    print()


def main():
    """Run the phishing URL detector interactively."""
    print("=" * 50)
    print("  Phishing URL Detector")
    print("=" * 50)

    while True:
        url = input("\nEnter a URL (or 'quit' to exit): ").strip()
        if url.lower() in ("quit", "exit", "q"):
            print("Goodbye!")
            break
        if not url:
            print("Please enter a valid URL.")
            continue

        score, label, reasons = analyze_url(url)
        display_result(url, score, label, reasons)


if __name__ == "__main__":
    main()