"""PhishGuard core: dataset, features, hybrid ML + rules, allow/block lists, .eml parsing."""
import os, re, csv, io, gzip, json, time, random, pickle, datetime
from markupsafe import Markup, escape
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse

import numpy as np
from scipy.sparse import hstack, csr_matrix
from sklearn.feature_extraction.text import TfidfVectorizer, ENGLISH_STOP_WORDS
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

BASE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE, "data")
DATA_PATH = os.path.join(DATA_DIR, "emails.csv")
MODEL_PATH = os.path.join(DATA_DIR, "model.pkl")
os.makedirs(DATA_DIR, exist_ok=True)
REAL_PATH = os.path.join(DATA_DIR, "real_emails.csv.gz")
csv.field_size_limit(10**8)

# Words that only identify the Enron source corpus (not real scam/legit signals) are ignored by the text model.
STOP = list(ENGLISH_STOP_WORDS | {"enron", "vince", "kaminski", "ect", "hou", "houston", "shirley", "crenshaw", "stinson", "pm", "cc", "subject", "forwarded"})
TOKEN = r"(?u)\b[^\W\d_]{2,}\b"
URL_RE = re.compile(r'https?://[^\s<>"\')\]]+', re.I)
IP_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rb.gy", "shorturl.at"}
BAD_TLDS = {"xyz", "top", "click", "tk", "ml", "ga", "cf", "gq", "work", "support", "zip", "info", "buzz"}
URGENT = ["urgent", "immediately", "verify your", "suspended", "locked", "within 24", "act now",
          "final notice", "confirm your", "unusual activity", "expire", "limited time", "click here",
          "update your", "security alert", "password", "account will be", "winner", "claim", "gift card",
          "blocked", "kyc", "refund", "registration fee", "deactivation"]
BRANDS = ["PayPal", "Amazon", "Microsoft", "Netflix", "HDFC Bank", "SBI", "Apple", "Google", "Facebook", "DHL", "Paytm"]


# ------------------------------------------------------------ dataset
def _phish_url(brand, r):
    b = brand.lower().replace(" ", "")
    t = sorted(BAD_TLDS)
    return r.choice([
        f"http://{b}-secure-verify.{r.choice(t)}/login",
        f"http://{r.randint(11,220)}.{r.randint(1,250)}.{r.randint(1,250)}.{r.randint(1,250)}/{b}/signin",
        f"https://{b}.account-update.{r.choice(t)}/verify?id={r.randint(1000,99999)}",
        f"https://bit.ly/{r.choice(['3xYz','aB9k','Qw12'])}{r.randint(10,99)}",
        f"http://{b}0{r.randint(1,9)}-support.{r.choice(t)}/",
        f"https://secure-login.{b}.com.verify-account.net/session/{r.randint(100,999)}",
    ])


def make_dataset(n=2000, seed=42):
    r = random.Random(seed)
    rows = []
    P = ["Dear customer, unusual activity was detected on your {b} account. Your account will be suspended within 24 hours. Verify your identity immediately: {u}",
         "URGENT: {b} security alert! Confirm your password now or your account will be locked. Click here {u}",
         "Congratulations! You are the winner of a {b} gift card worth $500. Claim your prize now: {u}",
         "Final notice: your {b} payment failed. Update your billing details immediately to avoid suspension {u}",
         "Hello user, your {b} mailbox is full and will expire. Login to keep your account {u} Act now!",
         "Dear valued member, we could not verify your details. Confirm your account information here: {u}",
         "Hi, your {b} KYC is incomplete and your account will be blocked today. Update PAN and Aadhaar now: {u}",
         "Dear Sir/Madam, you have a pending refund of Rs {n} from {b}. Submit your bank details to receive it: {u}",
         "Exciting job offer! Work from home and earn Rs 50000 per week. Pay a small registration fee and reply to this email today.",
         "Your {b} package could not be delivered. Pay the small redelivery fee here {u}",
         "IT helpdesk notice: your mailbox quota is exceeded. Re-validate your password at {u} to avoid deactivation.",
         "Please reply with your account number and password so we can reverse the unauthorized charge on your {b} account."]
    H = ["Hi team, the sprint review is scheduled for Thursday at 3 PM. Agenda attached. Let me know if you cannot attend.",
         "Hi, please find the invoice for last month attached. Payment is due by the end of the month. Thanks for your business.",
         "Your order has shipped and will arrive on Friday. Track it anytime at https://www.{d}/orders. Thank you for shopping with us.",
         "Weekly newsletter: five tips for writing cleaner code, plus upcoming meetups. Read more at https://{d}/blog/post-{n}",
         "Hey, are we still on for lunch tomorrow? I was thinking the place near the office. Cheers!",
         "Reminder: your interview is confirmed for Monday 10 AM. Meeting link: https://meet.google.com/abc-defg-hij. Best of luck!",
         "Thanks for signing up. You can change your password anytime from Settings at https://www.{d}/settings. Welcome aboard!",
         "Project update: the API tests are passing, deployment planned for next week. Pull request: https://github.com/team/repo/pull/{n}",
         "Your {b} receipt for the purchase on {n} is attached. If you have questions, reply to this email.",
         "{b} security notice: a new sign-in to your account from Chrome on Windows. If this was you, no action is needed. Manage devices at https://www.{d}/security",
         "Hi, attached is the offer letter for the Software Engineer role. Please sign and return by Friday. Welcome to the team!",
         "Class notes for unit {n} are uploaded to the shared drive: https://drive.google.com/drive/folders/{n}. Please review before the exam.",
         "You requested a password reset. Use this link within 1 hour: https://www.{d}/reset?token={n}. If you did not request this, ignore this email.",
         "Your {b} subscription renews on {n} Oct. No action needed. View details at https://www.{d}/account"]
    tail = ["", " Thanks, Support Team", " Regards, Security Dept", " Sent from my phone", " -- Priya"]
    for _ in range(n):
        b = r.choice(BRANDS)
        t = r.choice(P).format(b=b, u=_phish_url(b, r), n=r.randint(500, 9999))
        rows.append((t + r.choice(tail), 1))
    for _ in range(n):
        d = r.choice(["google.com", "microsoft.com", "github.com", "amazon.in", "linkedin.com", "wikipedia.org"])
        rows.append((r.choice(H).format(d=d, n=r.randint(1, 999), b=r.choice(BRANDS)) + r.choice(tail), 0))
    r.shuffle(rows)
    return rows


def ensure_dataset():
    if os.path.exists(DATA_PATH): return
    with open(DATA_PATH, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(["text", "label", "source"])
        if os.path.exists(REAL_PATH):  # real emails (Enron-Spam corpus sample)
            with gzip.open(REAL_PATH, "rt", newline="", encoding="utf-8") as g:
                for row in csv.DictReader(g): w.writerow([row["text"], row["label"], "real"])
        for t, l in make_dataset(1500): w.writerow([t, l, "synthetic"])


def read_dataset_full():
    ensure_dataset()
    X, y, src = [], [], []
    with open(DATA_PATH, newline="", encoding="utf-8", errors="ignore") as f:
        for row in csv.DictReader(f):
            if row.get("text") and row.get("label") in ("0", "1"):
                X.append(row["text"]); y.append(int(row["label"])); src.append(row.get("source") or "user")
    return X, y, src


def read_dataset():
    return read_dataset_full()[:2]


def dataset_info():
    X, y, src = read_dataset_full()
    return {"rows": len(y), "phishing": sum(y), "legit": len(y) - sum(y), "real": src.count("real"), "synthetic": src.count("synthetic"), "user": src.count("user")}


_POS = {"1", "phishing", "phish", "spam", "malicious", "scam"}


def import_csv(raw: bytes):
    """Append a user CSV (columns: text/body/message + label/class/type) to the dataset."""
    ensure_dataset()
    rd = csv.DictReader(io.StringIO(raw.decode("utf-8", "ignore")))
    cols = {(c or "").strip().lower(): c for c in (rd.fieldnames or [])}
    tc = next((cols[k] for k in ("text", "body", "message", "email text", "content") if k in cols), None)
    lc = next((cols[k] for k in ("label", "class", "type", "category") if k in cols), None)
    if not tc or not lc:
        raise ValueError("CSV needs a text column (text/body/message) and a label column (label/class/type).")
    n = 0
    with open(DATA_PATH, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        for row in rd:
            t = (row.get(tc) or "").strip()
            if t:
                w.writerow([t, 1 if (row.get(lc) or "").strip().lower() in _POS else 0, "user"]); n += 1
    return n


# ------------------------------------------------------------ features
def extract_urls(text):
    return [u.rstrip(".,;") for u in URL_RE.findall(text)]


def host_of(url):
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def domain_of(sender):
    m = re.findall(r"@([\w.-]+)", sender or "")
    return m[-1].lower().strip(".") if m else ""


def _match(host, dom):
    return host == dom or host.endswith("." + dom)


def rule_analysis(text, sender="", extras=None):
    extras = extras or {}
    pts, why = 0, []
    low = text.lower()
    hosts = [host_of(u) for u in extract_urls(text)]
    urls = extract_urls(text)

    def add(p, msg):
        nonlocal pts
        pts += p; why.append(msg)

    if any(IP_RE.match(h) for h in hosts): add(30, "A link uses a raw IP address instead of a domain name")
    if any(h in SHORTENERS for h in hosts): add(15, "A link uses a URL shortener that hides the real destination")
    if any("." in h and h.rsplit(".", 1)[-1] in BAD_TLDS for h in hosts): add(20, "A link ends in a domain extension often abused by scammers")
    if any(u.lower().startswith("http://") for u in urls): add(10, "A link is not encrypted (HTTP instead of HTTPS)")
    if any(h.count("-") >= 2 or h.count(".") >= 4 for h in hosts): add(10, "A link's domain looks unusually long or hyphen-heavy")
    if any("@" in u.split("//", 1)[-1].split("/")[0] for u in urls): add(20, "A link contains '@' to disguise the real host")
    for b in BRANDS:
        bl = b.lower().replace(" ", "")
        if any(bl in h and not re.search(rf"(^|\.){bl}\.(com|in|co\.in|net)$", h) for h in hosts):
            add(25, f"A link imitates {b} but does not go to its official domain"); break
    hits = [k for k in URGENT if k in low]
    if len(hits) >= 3: add(25, f"Heavy urgency / credential language ({', '.join(hits[:4])}...)")
    elif hits: add(8 * len(hits), f"Urgency / credential language ({', '.join(hits)})")
    if text.count("!") >= 3: add(5, "Excessive exclamation marks")
    if re.search(r"dear (customer|user|member|valued|sir)", low): add(8, "Generic greeting instead of your name")
    if extras.get("html_mismatch"): add(30, "A link's visible text shows a different site than where it really goes")
    if extras.get("reply_to_mismatch"): add(15, "Reply-To address differs from the sender's domain")
    if extras.get("auth_fail"): add(30, "Email failed SPF/DKIM/DMARC authentication")
    if extras.get("attachment_risky"): add(20, "Contains a risky attachment type (.exe, .zip, .html ...)")
    s = (sender or "").lower()
    for b in BRANDS:
        bl = b.lower().replace(" ", "")
        if bl in s and not re.search(rf"@([\w-]+\.)*{bl}\.(com|in|co\.in|net)", s):
            add(25, f"Sender name mentions {b} but the address is not from its official domain"); break
    return min(pts, 100), why


def _num(text):
    urls = extract_urls(text); hosts = [host_of(u) for u in urls]; low = text.lower()
    letters = [c for c in text if c.isalpha()]
    return [len(urls), sum(bool(IP_RE.match(h)) for h in hosts), sum(h in SHORTENERS for h in hosts),
            sum("." in h and h.rsplit(".", 1)[-1] in BAD_TLDS for h in hosts),
            sum(u.lower().startswith("http://") for u in urls), sum(k in low for k in URGENT),
            min(text.count("!"), 10), (sum(c.isupper() for c in letters) / len(letters)) if letters else 0,
            max([len(u) for u in urls] or [0]) / 100]


# ------------------------------------------------------------ model
class Model:
    def __init__(self):
        self.vec = TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True, stop_words=STOP, token_pattern=TOKEN)
        self.clf = LogisticRegression(max_iter=3000, C=3.0)
        self.meta = {}

    def _x(self, texts, fit=False):
        tf = self.vec.fit_transform(texts) if fit else self.vec.transform(texts)
        return hstack([tf, csr_matrix(np.array([_num(t) for t in texts]))]).tocsr()

    def train(self, X, y, src=None):
        src = src or ["user"] * len(y)
        idx = list(range(len(y)))
        tr, te = train_test_split(idx, test_size=0.2, random_state=1, stratify=y)
        self.clf.fit(self._x([X[i] for i in tr], fit=True), [y[i] for i in tr])
        p = self.clf.predict(self._x([X[i] for i in te]))
        yt = [y[i] for i in te]
        ri = [k for k, i in enumerate(te) if src[i] == "real"]
        self.meta = {"accuracy": round(accuracy_score(yt, p) * 100, 2), "precision": round(precision_score(yt, p) * 100, 2),
                     "recall": round(recall_score(yt, p) * 100, 2), "f1": round(f1_score(yt, p) * 100, 2),
                     "real_accuracy": round(accuracy_score([yt[k] for k in ri], [p[k] for k in ri]) * 100, 2) if ri else None,
                     "real_n": len(ri), "samples": len(y), "trained_at": datetime.datetime.now().strftime("%d %b %Y, %H:%M")}
        self.clf.fit(self._x(X, fit=True), y)  # final model learns from everything
        return self.meta

    def proba(self, text):
        return float(self.clf.predict_proba(self._x([text]))[0][1])


_MODEL = None


def retrain(extra=None):
    """Train on dataset + user-corrected scans (extra = [(text, label)], weighted x3)."""
    global _MODEL
    X, y, src = read_dataset_full()
    for t, l in (extra or []):
        X += [t] * 3; y += [l] * 3; src += ["feedback"] * 3
    m = Model(); m.train(X, y, src)
    with open(MODEL_PATH, "wb") as f: pickle.dump(m, f)
    _MODEL = m
    return m.meta


def load_or_train():
    global _MODEL
    if os.path.exists(MODEL_PATH):
        try:
            with open(MODEL_PATH, "rb") as f: _MODEL = pickle.load(f)
            return _MODEL
        except Exception:
            pass
    retrain()
    return _MODEL


def model_meta():
    return (_MODEL.meta if _MODEL else {}) or {}


def analyze(subject="", sender="", body="", extras=None, allow=(), block=(), intel=None):
    if _MODEL is None: load_or_train()
    extras = extras or {}
    text = f"{subject}\n{body}".strip()
    sd = domain_of(sender)
    urls = extract_urls(text)
    ml = _MODEL.proba(text) if text else 0.0
    rs, reasons = rule_analysis(text, sender, extras)
    score = round(100 * (0.5 * ml + 0.5 * rs / 100))
    if rs >= 60: score = max(score, 70)
    if any(_match(host_of(u), d) for u in urls for d in block) or any(sd and _match(sd, d) for d in block):
        score = max(score, 98); reasons.insert(0, "Sender or link is on YOUR blocklist")
    elif sd and any(_match(sd, d) for d in allow) and not extras.get("auth_fail"):
        score = min(score, 10); reasons.insert(0, "Sender domain is on YOUR allowlist (trusted)")
    if intel:
        score = min(100, score + intel.get("points", 0)); reasons += intel.get("reasons", [])
        if intel.get("hard"): score = max(score, 97); reasons = intel["hard"] + reasons
    verdict = "Phishing" if score >= 60 else "Suspicious" if score >= 35 else "Safe"
    return {"verdict": verdict, "score": score, "ml": round(ml * 100), "rules": rs, "sender_domain": sd,
            "reasons": reasons or ["No suspicious indicators found"], "urls": urls}


# ------------------------------------------------------------ .eml parsing
def parse_eml(raw: bytes):
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    subject, sender = str(msg["subject"] or ""), str(msg["from"] or "")
    hp, pp = msg.get_body(preferencelist=("html",)), msg.get_body(preferencelist=("plain",))
    html = hp.get_content() if hp else ""
    plain = pp.get_content() if pp else ""
    body = plain or re.sub(r"<[^>]+>", " ", html)
    extras = {}
    for href, txt in re.findall(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', html, re.I | re.S):
        shown = re.findall(r"(?:https?://)?([\w-]+(?:\.[\w-]+)+)", re.sub(r"<[^>]+>", "", txt))
        if shown and host_of(href) and re.sub(r"^www\.", "", shown[0].lower()) not in host_of(href):
            extras["html_mismatch"] = True
        body += f"\n{href}"
    reply, frm = domain_of(str(msg["reply-to"] or "")), domain_of(sender)
    if reply and frm and reply != frm: extras["reply_to_mismatch"] = True
    auth = (str(msg["authentication-results"] or "") + str(msg["received-spf"] or "")).lower()
    if re.search(r"(spf|dkim|dmarc)=(fail|softfail)|^\s*fail", auth): extras["auth_fail"] = True
    for part in msg.iter_attachments():
        if (part.get_filename() or "").lower().endswith((".exe", ".scr", ".js", ".vbs", ".bat", ".zip", ".html", ".iso")):
            extras["attachment_risky"] = True
    return subject, sender, body, extras


# ------------------------------------------------------------ extras: text highlighting + quiz
_KW = re.compile("|".join(re.escape(k) for k in sorted(URGENT, key=len, reverse=True)), re.I)


def highlight_html(text):
    spans = [(m.start(), m.end(), "url") for m in URL_RE.finditer(text)]
    spans += [(m.start(), m.end(), "kw") for m in _KW.finditer(text)
              if not any(m.start() < b and m.end() > a for a, b, _ in spans)]
    out, pos = [], 0
    for a, b, k in sorted(spans):
        tip = "Link - check where it really goes" if k == "url" else "Pressure / credential wording"
        out += [escape(text[pos:a]), Markup(f'<mark class="{k}" title="{tip}">'), escape(text[a:b]), Markup("</mark>")]
        pos = b
    out.append(escape(text[pos:]))
    return Markup("").join(out)


_QUIZ = None


def quiz_item():
    global _QUIZ
    if _QUIZ is None:
        X, y, src = read_dataset_full()
        _QUIZ = {0: [], 1: []}
        for t, l, s_ in zip(X, y, src):
            if 80 <= len(t) <= 650 and s_ in ("real", "synthetic"): _QUIZ[l].append((t, s_))
    label = random.choice([0, 1])
    real = [r for r in _QUIZ[label] if r[1] == "real"] or _QUIZ[label]
    text, s_ = random.choice(real if random.random() < 0.7 else _QUIZ[label])
    why = rule_analysis(text)[1] or (["Wording and structure match typical scam / spam mail"] if label else ["No pressure tactics, suspicious links or credential requests"])
    return {"text": text, "label": label, "why": why, "real": s_ == "real"}


# ------------------------------------------------------------ model lab (comparison + explainability)
COMPARE_PATH = os.path.join(DATA_DIR, "model_compare.json")


def compare_models():
    from sklearn.naive_bayes import MultinomialNB
    from sklearn.svm import LinearSVC
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import confusion_matrix
    X, y, _ = read_dataset_full()
    tr, te = train_test_split(list(range(len(y))), test_size=0.2, random_state=1, stratify=y)
    vec = TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True, stop_words=STOP, token_pattern=TOKEN, max_features=20000)

    def mat(ids, fit=False):
        t = [X[i] for i in ids]
        tf = vec.fit_transform(t) if fit else vec.transform(t)
        return hstack([tf, csr_matrix(np.array([_num(s) for s in t]))]).tocsr()

    Xtr, Xte = mat(tr, True), mat(te)
    ytr, yte = [y[i] for i in tr], [y[i] for i in te]
    models = [("Logistic Regression (deployed)", LogisticRegression(max_iter=3000, C=3.0)), ("Naive Bayes", MultinomialNB()),
              ("Linear SVM", LinearSVC(max_iter=10000)), ("Random Forest", RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=1))]
    out = []
    for name, m in models:
        t0 = time.time(); m.fit(Xtr, ytr); p = m.predict(Xte)
        out.append({"name": name, "accuracy": round(accuracy_score(yte, p) * 100, 2), "precision": round(precision_score(yte, p) * 100, 2),
                    "recall": round(recall_score(yte, p) * 100, 2), "f1": round(f1_score(yte, p) * 100, 2),
                    "seconds": round(time.time() - t0, 1), "cm": confusion_matrix(yte, p).tolist()})
    res = {"ran_at": datetime.datetime.now().strftime("%d %b %Y, %H:%M"), "train": len(tr), "test": len(te), "results": out}
    with open(COMPARE_PATH, "w") as f: json.dump(res, f)
    return res


def load_compare():
    try:
        with open(COMPARE_PATH) as f: return json.load(f)
    except Exception:
        return None


def top_words(k=14):
    if _MODEL is None: load_or_train()
    names = _MODEL.vec.get_feature_names_out()
    coef = _MODEL.clf.coef_[0][:len(names)]
    order = np.argsort(coef)
    return [names[i] for i in order[-k:][::-1]], [names[i] for i in order[:k]]
