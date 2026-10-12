# Intentionally vulnerable fixture for code.security tests.
import pickle
import subprocess

import requests
import yaml
from flask import Flask, redirect, request

app = Flask(__name__)


@app.route("/run")
def run():
    return subprocess.check_output("ls " + request.args["dir"], shell=True)


@app.route("/load")
def load():
    return pickle.loads(request.data)


@app.route("/config")
def config():
    unsafe = yaml.load(request.data)
    safe = yaml.load(request.data, Loader=yaml.SafeLoader)
    return str(unsafe) + str(safe)


@app.route("/user")
def user():
    cursor.execute(f"SELECT * FROM users WHERE name = '{request.args['name']}'")
    cursor.execute("SELECT * FROM users WHERE name = %s", (request.args["name"],))
    return "ok"


@app.route("/next")
def next_page():
    return redirect(request.args.get("url"))


def fetch():
    return requests.get("https://internal.example.com", verify=False)


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
