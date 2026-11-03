import os
import pickle
import subprocess
import hashlib
import random

import requests
import yaml
from flask import Flask, request

app = Flask(__name__)
SECRET_KEY = "s3cr3t-Pr0d-K3y-9f8a7b"


@app.route("/user")
def get_user(db):
    user_id = request.args.get("id")
    cursor = db.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()


@app.route("/ping")
def ping():
    host = request.args.get("host")
    return subprocess.check_output(f"ping -c 1 {host}", shell=True)


@app.route("/calc")
def calc():
    return str(eval(request.args.get("expr")))


@app.route("/load", methods=["POST"])
def load():
    obj = pickle.loads(request.data)
    cfg = yaml.load(request.form["config"])
    return str(obj) + str(cfg)


def fetch(url):
    return requests.get(url, verify=False)


def reset_token():
    token = str(random.randint(100000, 999999))
    return hashlib.md5(token.encode()).hexdigest()


def run_backup(path):
    os.system("tar czf /tmp/backup.tgz " + path)


def safe_example(expr):
    return eval(expr)  # vulnfind:ignore PY-EVAL  (demonstrates inline suppression)


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
