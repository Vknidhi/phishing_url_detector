# Phishing URL Detector

## About the Project

This is a small personal project I built to understand how phishing URLs work and how they can be detected using simple logic.

Phishing attacks often use misleading URLs to trick users into entering passwords or sensitive information. As a beginner in cybersecurity, I wanted to explore how some common phishing patterns can be identified using basic Python programming.

This project is completely rule-based and focuses more on learning concepts rather than building a perfect detection system.

---

## What This Project Does

- Takes a URL as input from the user
- Checks the URL for common phishing characteristics
- Assigns a risk score based on detected patterns
- Classifies the URL as:
  - **Safe** — Low risk score
  - **Suspicious** — Moderate risk score
  - **Phishing** — High risk score
- Displays the reasons why the URL was flagged

---

## Phishing Checks Used

The program looks for:

| # | Check | Score |
|---|-------|-------|
| 1 | Suspicious keywords (`login`, `verify`, `secure`, `bank`, etc.) | +1 |
| 2 | Unusually long URL (> 75 characters) | +1 |
| 3 | `@` symbol in the URL | +1 |
| 4 | IP address instead of a domain name | +2 |
| 5 | Missing HTTPS | +1 |
| 6 | Possible misspelling / typosquatting | +1 |
| 7 | Too many subdomains (more than 3 dots) | +1 |

Each check increases the overall risk score. A score of **5+** is flagged as phishing, **2–4** as suspicious, and **0–1** as safe.

---

## Requirements

- Python 3.x (no external dependencies — uses only the standard library)

---

## How to Run

1. Download or clone the repository:
   ```bash
   git clone https://github.com/Vknidhi/phishing_url_detector.git
   cd phishing_url_detector
   ```
2. Run the program:
   ```bash
   python phishing_url_detector.py
   ```
3. Enter a URL when prompted.

---

## Example Output

```
Enter a URL: http://192.168.1.1/login/verify?user=admin@secure

🔍 Analysis Result
🚨 PHISHING URL

Reasons:
- Contains suspicious keyword
- Contains '@' symbol
- Uses IP address instead of domain
- Does not use HTTPS
```

```
Enter a URL: https://www.google.com

🔍 Analysis Result
✅ SAFE URL
```

---

## Future Improvements

1. Add machine learning-based detection
2. Improve misspelling detection
3. Convert into a browser extension

---

## License

This project is open source and available for learning purposes.
