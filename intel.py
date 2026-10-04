"""Threat intelligence: real phishing-domain feed + optional live lookups (domain age, SPF/DMARC, Google Safe Browsing)."""
import gzip, os, re, json, datetime, urllib.request
from concurrent.futures import ThreadPoolExecutor, wait
import db
from detector import host_of, DATA_DIR

FEED_URL = "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt"
BUNDLED = os.path.join(DATA_DIR, "threat_domains.txt.gz")
TRUSTED = set("""google.com microsoft.com apple.com amazon.com amazon.in paypal.com netflix.com facebook.com instagram.com
linkedin.com github.com wikipedia.org twitter.com x.com youtube.com yahoo.com outlook.com live.com office.com dropbox.com
zoom.us slack.com adobe.com ebay.com flipkart.com paytm.com hdfcbank.com sbi.co.in icicibank.com axisbank.com whatsapp.com
gmail.com cloudflare.com stackoverflow.com mozilla.org python.org""".split())


def _clean(lines):
    for l in lines:
        l = l.strip().lower()
        if l and "/" not in l and " " not in l and "." in l and not l.startswith("#"):
            yield l


def load_bundled():
    if db.feed_count() == 0 and os.path.exists(BUNDLED):
        print("Loading phishing-domain database (first run only, a few seconds)...")
        with gzip.open(BUNDLED, "rt", encoding="utf-8", errors="ignore") as f:
            n = db.replace_feed(_clean(f), "bundled snapshot")
        print(f"Loaded {n:,} known phishing domains.")


def update_feed():
    req = urllib.request.Request(FEED_URL, headers={"User-Agent": "PhishGuard"})
    with urllib.request.urlopen(req, timeout=90) as r:
        text = r.read().decode("utf-8", "ignore")
    return db.replace_feed(_clean(text.splitlines()), "Phishing.Database (live download)")


def candidates(host):
    parts = host.split(".")
    return [".".join(parts[i:]) for i in range(len(parts) - 1) if ".".join(parts[i:]) not in TRUSTED]


def apex(host):
    p = host.split(".")
    if len(p) >= 3 and len(p[-1]) == 2 and p[-2] in {"co", "com", "org", "net", "gov", "ac"}: return ".".join(p[-3:])
    return ".".join(p[-2:])


# ---- live lookups (every one fails safe: no internet -> signal simply skipped)
def _age_days(domain):
    req = urllib.request.Request(f"https://rdap.org/domain/{domain}", headers={"User-Agent": "PhishGuard", "Accept": "application/rdap+json"})
    with urllib.request.urlopen(req, timeout=5) as r:
        data = json.load(r)
    for e in data.get("events", []):
        if e.get("eventAction") == "registration":
            d = datetime.datetime.fromisoformat(e["eventDate"].replace("Z", "+00:00"))
            return (datetime.datetime.now(datetime.timezone.utc) - d).days
    return None


def _dns_auth(domain):
    import dns.resolver, dns.exception
    def txt(name):
        try:
            return " ".join(str(a) for a in dns.resolver.resolve(name, "TXT", lifetime=3)).lower()
        except dns.resolver.NXDOMAIN: return "NX"
        except dns.resolver.NoAnswer: return ""
    base = txt(domain)
    if base == "NX": return {"exists": False}
    return {"exists": True, "spf": "v=spf1" in base, "dmarc": "v=dmarc1" in txt("_dmarc." + domain)}


def _safe_browsing(urls, key):
    body = {"client": {"clientId": "phishguard", "clientVersion": "3"}, "threatInfo": {
        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"], "platformTypes": ["ANY_PLATFORM"],
        "threatEntryTypes": ["URL"], "threatEntries": [{"url": u} for u in urls[:20]]}}
    req = urllib.request.Request(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}",
                                 data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=6) as r:
        return json.load(r).get("matches", [])


def check(urls, sender_domain, live=True, sb_key=""):
    out = {"hard": [], "points": 0, "reasons": [], "live_ok": []}
    hosts = list(dict.fromkeys(h for h in (host_of(u) for u in urls) if h))
    if sender_domain: hosts_s = [sender_domain]
    else: hosts_s = []
    for h in hosts + hosts_s:
        hit = db.feed_hit(candidates(h))
        if hit:
            out["hard"].append(f"'{h}' is listed in the known-phishing domain database ({hit})"); break
    if not live: return out
    pool = ThreadPoolExecutor(max_workers=8)
    jobs = {}
    for h in [x for x in hosts if not re.match(r"^\d+(\.\d+){3}$", x) and apex(x) not in TRUSTED][:3]:
        jobs[pool.submit(_age_days, apex(h))] = ("age", apex(h))
    if sender_domain and apex(sender_domain) not in TRUSTED:
        jobs[pool.submit(_dns_auth, sender_domain)] = ("dns", sender_domain)
    if sb_key and urls:
        jobs[pool.submit(_safe_browsing, urls, sb_key)] = ("sb", "")
    done, _ = wait(jobs, timeout=9)
    for f in done:
        kind, name = jobs[f]
        try: res = f.result()
        except Exception: continue  # offline / rate-limited: skip this signal
        if kind == "age" and res is not None:
            if res < 30: out["points"] += 30; out["reasons"].append(f"Link domain {name} was registered only {res} days ago")
            elif res < 180: out["points"] += 10; out["reasons"].append(f"Link domain {name} is fairly new ({res} days old)")
            else: out["live_ok"].append(f"{name} is {res // 365 or 1}+ yr old" if res >= 365 else f"{name} is {res} days old")
        elif kind == "dns":
            if not res["exists"]: out["points"] += 25; out["reasons"].append(f"Sender domain {name} does not exist")
            elif not res["spf"] and not res["dmarc"]: out["points"] += 10; out["reasons"].append(f"Sender domain {name} has no SPF or DMARC email-authentication records")
            else: out["live_ok"].append(f"sender domain has email authentication records")
        elif kind == "sb" and res:
            out["hard"].append("Google Safe Browsing reports a link in this email as dangerous")
    pool.shutdown(wait=False, cancel_futures=True)
    if out["live_ok"] and not out["reasons"] and not out["hard"]:
        out["reasons"].append("Live checks passed: " + "; ".join(out["live_ok"]))
    return out
