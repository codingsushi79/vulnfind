# Labelled benchmark case: `expect: RULE` = must be flagged on this line, `safe` = must not be.
import os, pickle, subprocess, yaml, requests
from flask import Flask, request, redirect, render_template_string

app = Flask(__name__)


def build(name):
    return "SELECT * FROM users WHERE name = '%s'" % name


@app.route("/a")
def a(db):
    q = build(request.args.get("name"))
    db.cursor().execute(q)  # expect: PY-TAINT-SQLI
    db.cursor().execute("SELECT * FROM t WHERE id = %s", (request.args.get("id"),))  # safe
    n = int(request.args.get("n"))
    os.system("echo %d" % n)  # safe


@app.route("/b/<fname>")
def b(fname):
    return open(os.path.join("/srv", fname)).read()  # expect: PY-TAINT-PATH


@app.route("/c")
def c():
    subprocess.run("ping " + request.args["h"], shell=True)  # expect: PY-TAINT-CMDI
    data = pickle.loads(request.data)  # expect: PY-TAINT-DESER
    cfg = yaml.load(request.form["c"])  # expect: PY-TAINT-DESER
    safe_cfg = yaml.safe_load(request.form["c"])  # safe
    requests.get(request.form["url"], timeout=3)  # expect: PY-TAINT-SSRF
    render_template_string("Hi " + request.args["n"])  # expect: PY-TAINT-SSTI
    x = "constant"
    eval(x)  # safe
    return redirect(request.args.get("next"))  # expect: PY-TAINT-REDIRECT


def helpers():
    hashlib.md5(b"x")  # expect: PY-WEAK-HASH
    requests.get("https://example.com", verify=False, timeout=3)  # expect: PY-TLS-VERIFY-OFF
    msg = "never call eval(x) here"  # safe
