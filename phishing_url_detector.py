# Phishing URL Detector
# Rule-based cybersecurity project

import re

# Take URL input
url = input("Enter a URL: ").lower()

# List of suspicious keywords
suspicious_words = [
    "login", "verify", "secure", "account",
    "update", "bank", "free", "password", "confirm"
]

# Characters often used in misspellings
misspellings = ["0", "1", "@"]

score = 0
reasons = []

# Rule 1: Suspicious keywords
for word in suspicious_words:
    if word in url:
        score += 1
        reasons.append("Contains suspicious keyword")
        break

# Rule 2: Long URL
if len(url) > 75:
    score += 1
    reasons.append("URL is unusually long")

# Rule 3: '@' symbol trick
if "@" in url:
    score += 1
    reasons.append("Contains '@' symbol")

# Rule 4: IP address instead of domain
if re.search(r"\d+\.\d+\.\d+\.\d+", url):
    score += 2
    reasons.append("Uses IP address instead of domain")

# Rule 5: HTTPS check
if not url.startswith("https"):
    score += 1
    reasons.append("Does not use HTTPS")

# Rule 6: Misspelling / typosquatting
for char in misspellings:
    if char in url:
        score += 1
        reasons.append("Possible misspelling detected")
        break

# Rule 7: Too many subdomains
if url.count('.') > 3:
    score += 1
    reasons.append("Too many subdomains detected")

# Final result
print("\n🔍 Analysis Result")

if score >= 5:
    print("🚨 PHISHING URL")
elif score >= 2:
    print("⚠️ SUSPICIOUS URL")
else:
    print("✅ SAFE URL")

if reasons:
    print("\nReasons:")
    for r in reasons:
        print("-", r)