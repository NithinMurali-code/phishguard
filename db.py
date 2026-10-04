"""SQLite storage: scan history, user feedback, allow/block lists."""
import sqlite3, json, os, datetime

DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "phishguard.db")


def conn():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c


def init():
    with conn() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, source TEXT, sender TEXT,
            sender_domain TEXT, subject TEXT, body TEXT, verdict TEXT, score INT, ml INT, rules INT,
            reasons TEXT, urls TEXT, user_label INT);
        CREATE TABLE IF NOT EXISTS domains(id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT, kind TEXT, UNIQUE(domain, kind));
        """)


def _row(r):
    d = dict(r)
    d["reasons"] = json.loads(d["reasons"] or "[]"); d["urls"] = json.loads(d["urls"] or "[]")
    return d


def save_scan(r, sender, subject, body, source):
    with conn() as c:
        cur = c.execute("INSERT INTO scans(ts,source,sender,sender_domain,subject,body,verdict,score,ml,rules,reasons,urls) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                        (datetime.datetime.now().strftime("%Y-%m-%d %H:%M"), source, sender, r["sender_domain"], subject, body,
                         r["verdict"], r["score"], r["ml"], r["rules"], json.dumps(r["reasons"]), json.dumps(r["urls"])))
        return cur.lastrowid


def get_scan(sid):
    with conn() as c:
        r = c.execute("SELECT * FROM scans WHERE id=?", (sid,)).fetchone()
    return _row(r) if r else None


def list_scans(q="", verdict="", limit=200):
    sql, args = "SELECT * FROM scans WHERE 1=1", []
    if q:
        sql += " AND (subject LIKE ? OR sender LIKE ? OR body LIKE ?)"; args += [f"%{q}%"] * 3
    if verdict:
        sql += " AND verdict=?"; args.append(verdict)
    with conn() as c:
        return [_row(r) for r in c.execute(sql + " ORDER BY id DESC LIMIT ?", args + [limit])]


def delete_scan(sid):
    with conn() as c: c.execute("DELETE FROM scans WHERE id=?", (sid,))


def clear_scans():
    with conn() as c: c.execute("DELETE FROM scans")


def set_feedback(sid, label):
    with conn() as c: c.execute("UPDATE scans SET user_label=? WHERE id=?", (label, sid))


def feedback_samples():
    with conn() as c:
        return [(f"{r['subject']}\n{r['body']}".strip(), r["user_label"])
                for r in c.execute("SELECT subject,body,user_label FROM scans WHERE user_label IS NOT NULL")]


def domains(kind):
    with conn() as c:
        return [r["domain"] for r in c.execute("SELECT domain FROM domains WHERE kind=?", (kind,))]


def domain_rows(kind):
    with conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM domains WHERE kind=? ORDER BY id DESC", (kind,))]


def add_domain(domain, kind):
    d = domain.strip().lower().replace("http://", "").replace("https://", "").split("/")[0].lstrip("@")
    if not d or "." not in d: return False
    with conn() as c: c.execute("INSERT OR IGNORE INTO domains(domain,kind) VALUES(?,?)", (d, kind))
    return True


def remove_domain(did):
    with conn() as c: c.execute("DELETE FROM domains WHERE id=?", (did,))


def stats():
    with conn() as c:
        by = {r["verdict"]: r["n"] for r in c.execute("SELECT verdict, COUNT(*) n FROM scans GROUP BY verdict")}
        days = {r["d"]: (r["n"], r["p"] or 0) for r in c.execute(
            "SELECT substr(ts,1,10) d, COUNT(*) n, SUM(verdict='Phishing') p FROM scans GROUP BY d")}
        top = [dict(r) for r in c.execute("SELECT sender_domain d, COUNT(*) n FROM scans WHERE verdict!='Safe' AND sender_domain!='' GROUP BY d ORDER BY n DESC LIMIT 5")]
        fb = c.execute("SELECT COUNT(*) FROM scans WHERE user_label IS NOT NULL").fetchone()[0]
    week = []
    for i in range(6, -1, -1):
        day = datetime.date.today() - datetime.timedelta(days=i)
        n, p = days.get(day.isoformat(), (0, 0))
        week.append({"label": day.strftime("%a"), "n": n, "p": p})
    return {"total": sum(by.values()), "safe": by.get("Safe", 0), "suspicious": by.get("Suspicious", 0),
            "phishing": by.get("Phishing", 0), "week": week, "wmax": max([w["n"] for w in week] + [1]), "top": top, "feedback": fb}


# ---------------------------------------------------------------- settings, threat feed, API key
def init_v3():
    with conn() as c:
        c.executescript("""CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT);
                           CREATE TABLE IF NOT EXISTS threats(domain TEXT PRIMARY KEY) WITHOUT ROWID;""")


def get_setting(k, default=""):
    with conn() as c:
        r = c.execute("SELECT v FROM settings WHERE k=?", (k,)).fetchone()
    return r["v"] if r else default


def set_setting(k, v):
    with conn() as c: c.execute("INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, str(v)))


def feed_count():
    with conn() as c: return c.execute("SELECT COUNT(*) FROM threats").fetchone()[0]


def replace_feed(domains, source):
    """Atomically swap in a new set of known-phishing domains."""
    with conn() as c:
        c.execute("DELETE FROM threats")
        c.executemany("INSERT OR IGNORE INTO threats(domain) VALUES(?)", ((d,) for d in domains))
    n = feed_count()
    set_setting("feed_source", source); set_setting("feed_updated", datetime.datetime.now().strftime("%d %b %Y, %H:%M"))
    return n


def feed_hit(candidates):
    if not candidates: return None
    with conn() as c:
        r = c.execute(f"SELECT domain FROM threats WHERE domain IN ({','.join('?' * len(candidates))}) LIMIT 1", candidates).fetchone()
    return r["domain"] if r else None
