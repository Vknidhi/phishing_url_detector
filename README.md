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
  - Safe
  - Suspicious
  - Phishing
- Displays the reasons why the URL was flagged

---

## Phishing Checks Used
The program looks for:
- Suspicious words like `login`, `verify`, `secure`, `bank`, etc.
- Very long URLs
- Usage of `@` symbol inside the URL
- URLs that use IP addresses instead of domain names
- URLs that do not use HTTPS
- Possible misspellings (like `micros0ft`, `paypa1`)
- Too many subdomains in the URL

Each of these checks increases the overall risk score.

---

## How to Run
1. Download or clone the repository
2. Open a terminal inside the project folder
3. Run the program using:
## Future Improvements
1. Add machine learning based detection
2. Improve misspelling detection
3. convert into a browser extension
