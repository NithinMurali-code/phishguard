# PhishGuard v3 - Email Phishing Detector

## Run
Windows: double-click `run.bat`   |   Mac/Linux: `./run.sh`
Or: `pip install -r requirements.txt` then `python app.py` (opens http://127.0.0.1:5000).
First start loads the phishing-domain database (a few seconds).

## What is real here
- ~392,000 real known-phishing domains (Phishing.Database snapshot) checked against every link and sender.
  Settings > "Update from internet" downloads the latest list.
- Live lookups (need internet): domain registration age (RDAP), sender SPF/DMARC records (DNS),
  optional Google Safe Browsing API key.
- SQLite database (data/phishguard.db): scan history, trusted/blocked domains, settings, feedback.
- REST API (/api/v1/...) with API key - see the API page in the app.
- ~5,000 real emails (public Enron-Spam corpus sample) + generated examples train the text model.
  Accuracy is reported separately on held-out REAL emails (about 98-99%); real-world mail will vary.
- Extras: live preview while typing, highlighted warning signs, animated gauge, dark mode, drag-and-drop .eml,
  'Spot the phish' quiz game, printable reports.
- Bulk scan: upload a CSV of emails, get a results table and a downloadable CSV.
- Model lab: compares Logistic Regression, Naive Bayes, Linear SVM and Random Forest, with a confusion
  matrix and the words the model has learned.
- Text model: TF-IDF + Logistic Regression + rule engine. Import real labelled emails in
  Data & settings and retrain to improve it.

## Accuracy
No detector is 100% accurate. A link on the known-phishing list is near-certain; everything else is a
risk estimate. Use the feedback buttons and retrain to adapt it to your own mail.
