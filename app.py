import csv, io, hmac, secrets, threading, webbrowser
from functools import wraps
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, Response, abort
import detector, db, intel

app = Flask(__name__)
app.secret_key = "phishguard-local-app"
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024
db.init(); db.init_v3()
if not db.get_setting("api_key"): db.set_setting("api_key", "pg_" + secrets.token_urlsafe(24))
if not db.get_setting("live"): db.set_setting("live", "1")
intel.load_bundled()
detector.load_or_train()


def run_scan(sender, subject, body, extras, source, save=True):
    urls = detector.extract_urls(f"{subject}\n{body}")
    sd = detector.domain_of(sender)
    info = intel.check(urls, sd, db.get_setting("live") == "1", db.get_setting("sb_key"))
    r = detector.analyze(subject, sender, body, extras, db.domains("allow"), db.domains("block"), info)
    return (db.save_scan(r, sender, subject, body, source) if save else None), r


@app.route("/")
def dashboard():
    return render_template("dashboard.html", s=db.stats(), recent=db.list_scans(limit=6), meta=detector.model_meta(), feed=db.feed_count(), fed=db.get_setting("feed_updated"))


@app.route("/scan", methods=["GET", "POST"])
def scan():
    if request.method == "POST":
        f = request.files.get("file")
        try:
            if f and f.filename:
                subject, sender, body, extras = detector.parse_eml(f.read()); src = "eml file"
            else:
                sender, subject, body = (request.form.get(k, "") for k in ("sender", "subject", "body")); extras = {}; src = "pasted"
        except Exception as e:
            flash(f"Could not read that file: {e}"); return redirect(url_for("scan"))
        if not (subject.strip() or body.strip()):
            flash("Paste an email or upload a .eml file first."); return redirect(url_for("scan"))
        sid, _ = run_scan(sender, subject, body, extras, src)
        return redirect(url_for("detail", sid=sid))
    return render_template("scan.html")


@app.route("/scan/<int:sid>")
def detail(sid):
    s = db.get_scan(sid) or abort(404)
    return render_template("detail.html", s=s, hl=detector.highlight_html(s["body"]))


@app.post("/live-check")
def live_check():
    d = request.get_json(silent=True) or {}
    text = f"{d.get('subject', '')}\n{d.get('body', '')}"
    if not text.strip(): return jsonify(empty=True)
    info = intel.check(detector.extract_urls(text), detector.domain_of(d.get("sender", "")), live=False)
    r = detector.analyze(d.get("subject", ""), d.get("sender", ""), d.get("body", ""), {}, db.domains("allow"), db.domains("block"), info)
    return jsonify(verdict=r["verdict"], score=r["score"], reasons=r["reasons"][:3])


@app.route("/models", methods=["GET", "POST"])
def models():
    if request.method == "POST":
        detector.compare_models(); flash("Model comparison finished.")
        return redirect(url_for("models"))
    pos, neg = detector.top_words()
    return render_template("models.html", res=detector.load_compare(), pos=pos, neg=neg, meta=detector.model_meta())


@app.route("/bulk", methods=["GET", "POST"])
def bulk():
    if request.method == "GET": return render_template("bulk.html", rows=None)
    f = request.files.get("file")
    try:
        rd = csv.DictReader(io.StringIO(f.read().decode("utf-8", "ignore")))
        cols = {(c or "").strip().lower(): c for c in (rd.fieldnames or [])}
        col = lambda *ks: next((cols[k] for k in ks if k in cols), None)
        sc, fc, bc = col("subject"), col("sender", "from"), col("body", "text", "message", "content")
        if not bc: raise ValueError("CSV needs a body column (body / text / message).")
        rows = []
        for i, row in enumerate(rd):
            if i >= 300: break
            subj, snd, body = (row.get(sc) or "") if sc else "", (row.get(fc) or "") if fc else "", row.get(bc) or ""
            if not (subj.strip() or body.strip()): continue
            urls = detector.extract_urls(f"{subj}\n{body}")
            info = intel.check(urls, detector.domain_of(snd), live=False)
            r = detector.analyze(subj, snd, body, {}, db.domains("allow"), db.domains("block"), info)
            sid = db.save_scan(r, snd, subj, body, "bulk")
            rows.append({"id": sid, "subject": subj, "sender": snd, "verdict": r["verdict"], "score": r["score"], "reason": r["reasons"][0]})
    except Exception as e:
        flash(f"Could not read that CSV: {e}"); return redirect(url_for("bulk"))
    out = io.StringIO(); w = csv.writer(out); w.writerow(["subject", "sender", "verdict", "score", "top_reason"])
    for r in rows: w.writerow([r["subject"], r["sender"], r["verdict"], r["score"], r["reason"]])
    return render_template("bulk.html", rows=rows, csv=out.getvalue())


@app.route("/bulk/sample.csv")
def bulk_sample():
    s = ("subject,sender,body\nAccount suspended,help@paypal-secure.xyz,Verify your password immediately http://192.168.4.7/login\n"
         "Lunch?,sam@gmail.com,Are we still on for lunch tomorrow?\nYou won!,promo@win-big.top,Claim your gift card now: https://bit.ly/3xYz12\n")
    return Response(s, mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=sample_emails.csv"})


@app.route("/quiz")
def quiz():
    return render_template("quiz.html")


@app.get("/quiz/next")
def quiz_next():
    return jsonify(detector.quiz_item())


@app.post("/scan/<int:sid>/feedback")
def feedback(sid):
    db.set_feedback(sid, int(request.form["label"]))
    flash("Thanks - saved your correction. Retrain the model from Data & settings to learn from it.")
    return redirect(url_for("detail", sid=sid))


@app.post("/scan/<int:sid>/delete")
def delete(sid):
    db.delete_scan(sid); flash("Scan deleted."); return redirect(url_for("history"))


@app.route("/history")
def history():
    q, v = request.args.get("q", "").strip(), request.args.get("verdict", "")
    return render_template("history.html", rows=db.list_scans(q, v), q=q, v=v)


@app.post("/history/clear")
def clear():
    db.clear_scans(); flash("History cleared."); return redirect(url_for("history"))


@app.route("/export.csv")
def export():
    out = io.StringIO(); w = csv.writer(out)
    w.writerow(["id", "time", "source", "sender", "subject", "verdict", "score", "your_label", "reasons"])
    for r in db.list_scans(limit=100000):
        w.writerow([r["id"], r["ts"], r["source"], r["sender"], r["subject"], r["verdict"], r["score"],
                    {1: "phishing", 0: "safe"}.get(r["user_label"], ""), " | ".join(r["reasons"])])
    return Response(out.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=phishguard_history.csv"})


@app.route("/settings")
def settings():
    return render_template("settings.html", allow=db.domain_rows("allow"), block=db.domain_rows("block"),
                           info=detector.dataset_info(), meta=detector.model_meta(), fb=db.stats()["feedback"], feed=db.feed_count(),
                           fed=db.get_setting("feed_updated"), fsrc=db.get_setting("feed_source"), live=db.get_setting("live") == "1", sbk=bool(db.get_setting("sb_key")))


@app.post("/domains/add")
def add_domain():
    kind = request.form.get("kind")
    if kind in ("allow", "block") and db.add_domain(request.form.get("domain", ""), kind):
        flash("Domain added.")
    else:
        flash("Enter a valid domain such as example.com")
    return redirect(url_for("settings"))


@app.post("/domains/<int:did>/remove")
def remove_domain(did):
    db.remove_domain(did); return redirect(url_for("settings"))


@app.post("/dataset/import")
def import_dataset():
    f = request.files.get("file")
    try:
        n = detector.import_csv(f.read()); flash(f"Added {n} rows to the dataset. Click 'Retrain model' to use them.")
    except Exception as e:
        flash(str(e))
    return redirect(url_for("settings"))


@app.post("/retrain")
def retrain():
    extra = db.feedback_samples(); m = detector.retrain(extra)
    flash(f"Model retrained on {m['samples']} samples (incl. {len(extra)} of your corrections). Test accuracy {m['accuracy']}%.")
    return redirect(url_for("settings"))


@app.post("/feed/update")
def feed_update():
    try:
        n = intel.update_feed(); flash(f"Threat database updated: {n:,} known phishing domains.")
    except Exception as e:
        flash(f"Could not download the feed (check your internet connection): {e}")
    return redirect(url_for("settings"))


@app.post("/settings/intel")
def intel_settings():
    db.set_setting("live", "1" if request.form.get("live") else "0")
    if request.form.get("sb_key", "").strip(): db.set_setting("sb_key", request.form["sb_key"].strip())
    if request.form.get("clear_key"): db.set_setting("sb_key", "")
    flash("Settings saved."); return redirect(url_for("settings"))


# ---------------------------------------------------------------- REST API (key required)
def need_key(f):
    @wraps(f)
    def w(*a, **k):
        key = request.headers.get("X-API-Key") or request.headers.get("Authorization", "").replace("Bearer ", "")
        if not hmac.compare_digest(key.encode(), db.get_setting("api_key").encode()):
            return jsonify(error="Invalid or missing API key. Send it as the X-API-Key header."), 401
        return f(*a, **k)
    return w


@app.route("/api-docs")
def api_docs():
    return render_template("api.html", key=db.get_setting("api_key"), base=request.host_url.rstrip("/"))


@app.post("/api-docs/regenerate")
def regen():
    db.set_setting("api_key", "pg_" + secrets.token_urlsafe(24)); flash("New API key generated. The old one no longer works.")
    return redirect(url_for("api_docs"))


@app.get("/api/v1/health")
def api_health():
    return jsonify(status="ok", threat_domains=db.feed_count(), model_accuracy=detector.model_meta().get("accuracy"))


@app.post("/api/v1/scan")
@need_key
def api_scan():
    d = request.get_json(silent=True) or {}
    if not (d.get("subject") or d.get("body")): return jsonify(error="Provide 'subject' and/or 'body' (optional: 'sender', 'save')."), 400
    sid, r = run_scan(d.get("sender", ""), d.get("subject", ""), d.get("body", ""), {}, "api", d.get("save", True))
    return jsonify(dict(r, id=sid))


@app.post("/api/v1/check-url")
@need_key
def api_url():
    u = (request.get_json(silent=True) or {}).get("url", "")
    if not u.startswith("http"): return jsonify(error="Provide a full 'url' starting with http(s)://"), 400
    _, r = run_scan("", "", u, {}, "api", save=False)
    return jsonify(url=u, verdict=r["verdict"], score=r["score"], reasons=r["reasons"])


@app.get("/api/v1/scans")
@need_key
def api_list():
    rows = db.list_scans(request.args.get("q", ""), request.args.get("verdict", ""), min(int(request.args.get("limit", 50)), 500))
    return jsonify(count=len(rows), scans=[{k: r[k] for k in ("id", "ts", "sender", "subject", "verdict", "score", "reasons")} for r in rows])


@app.get("/api/v1/scans/<int:sid>")
@need_key
def api_get(sid):
    r = db.get_scan(sid)
    return (jsonify(r) if r else (jsonify(error="Not found"), 404))


@app.get("/api/v1/stats")
@need_key
def api_stats():
    return jsonify(db.stats())


if __name__ == "__main__":
    url = "http://127.0.0.1:5000"
    print(f"PhishGuard running at {url}  (press Ctrl+C to stop)")
    threading.Timer(1.5, lambda: webbrowser.open(url)).start()
    app.run(host="127.0.0.1", port=5000)
