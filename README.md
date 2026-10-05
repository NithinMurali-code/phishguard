<img width="1535" height="777" alt="image" src="https://github.com/user-attachments/assets/b59a4db2-0d4a-42d9-9c78-7cdfed635240" /># PhishGuard - Email Phishing Detector

---

## Run
Windows: double-click `run.bat`   |   Mac/Linux: `./run.sh`
Or: `pip install -r requirements.txt` then `python app.py` (opens http://127.0.0.1:5000).
First start loads the phishing-domain database (a few seconds).

---

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

---

## Accuracy
No detector is 100% accurate. A link on the known-phishing list is near-certain; everything else is a
risk estimate. Use the feedback buttons and retrain to adapt it to your own mail.

---

## 📸 Screenshots

<img width="1520" height="777" alt="image" src="https://github.com/user-attachments/assets/276ed01e-be07-44d6-9ccc-2d420c36783c" />

<img width="1522" height="777" alt="image" src="https://github.com/user-attachments/assets/78353029-8167-40f2-8684-c15dca1ca400" />

<img width="1528" height="776" alt="image" src="https://github.com/user-attachments/assets/5f3ec052-eb02-45f9-b3c3-b57dd0f87e14" />

<img width="1535" height="777" alt="image" src="https://github.com/user-attachments/assets/ad406d0d-20dd-4c25-ba47-52bf0958cce6" />

<img width="1532" height="773" alt="image" src="https://github.com/user-attachments/assets/d8d834dc-90e7-4946-9825-4587ba44fafc" />

<img width="1533" height="772" alt="image" src="https://github.com/user-attachments/assets/2acdd8c5-7209-4cb6-b285-6999ce13af31" />

<img width="1527" height="773" alt="image" src="https://github.com/user-attachments/assets/f2546149-fcb2-484a-b8ed-34cd600960a8" />

<img width="1533" height="768" alt="image" src="https://github.com/user-attachments/assets/8e3f851c-860a-4128-864e-d6e68c80d1f1" />

<img width="1535" height="772" alt="image" src="https://github.com/user-attachments/assets/4c7b0c0a-fe8e-433f-98ce-4701b7155b60" />

<img width="1533" height="776" alt="image" src="https://github.com/user-attachments/assets/afdd7374-6441-4e09-8c08-ea2b6a75ec30" />

<img width="1535" height="777" alt="image" src="https://github.com/user-attachments/assets/7f25cda6-c18d-43a3-b664-a58999ab8788" />

<img width="1535" height="776" alt="image" src="https://github.com/user-attachments/assets/cb4f3bf5-cee6-4d02-9c6f-c0ad5ff9adfe" />

<img width="1535" height="777" alt="image" src="https://github.com/user-attachments/assets/c7ab4ab5-cc30-4a10-98e0-66b796bd50d7" />

---
