import hashlib
import os
import pickle
import sqlite3
import subprocess

import yaml
from flask import Flask, abort, redirect, render_template_string, request, send_file
from markupsafe import escape

app = Flask(__name__)
DB = sqlite3.connect(':memory:', check_same_thread=False)
FILES = '/srv/files'
ALLOWED_NEXT = {'/home', '/account'}
PAGE_SIZE = 20

def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


@app.route("/register", methods=["POST"])
def register():
    DB.execute("INSERT INTO users VALUES (?, ?)", (request.form["user"], hash_password(request.form["password"])))
    return {"ok": True}
