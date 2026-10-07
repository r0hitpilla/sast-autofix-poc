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

def cache_path(url: str) -> str:
    """File name for a cached page. Not a security use: any hash would do."""
    return os.path.join("/tmp/cache", hashlib.md5(url.encode()).hexdigest())
