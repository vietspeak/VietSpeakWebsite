import sqlite3
import json
from functools import wraps
from flask import Flask, render_template, request, g, session, redirect, url_for
from flask.json import jsonify
from flask_bcrypt import Bcrypt

constant_data = None
with open("constant.json", "r") as f:
    constant_data = json.load(f) 
DATABASE = constant_data["PATH_TO_DATABASE"]
app = Flask(__name__)
app.secret_key = constant_data["SESSION_SECRET_KEY"]
bcrypt = Bcrypt(app)
accepted_methods = ["POST", "GET"]

def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    get_db().commit()
    return (rv[0] if rv else None) if one else rv


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("username") is None:
            return redirect(url_for("home_page"))
        return f(*args, **kwargs)
    
    return decorated_function

@app.route("/")
def home_page():
    return render_template("index.html")

def get_password(username):
    query_str = "SELECT password FROM users WHERE username = ?"
    r = query_db(query_str, (username, ))
    if len(r) == 0:
        return None
    else:
        return r[0]["password"]

 
@app.route("/register", methods=accepted_methods)
def register():
    username = request.json.get("username", "")
    password = request.json.get("password", "")
    password_hashed = bcrypt.generate_password_hash(password).decode('utf-8')

    if get_password(username) is not None:
        return jsonify({
            "status": False
        })
    else:
        query_str = "INSERT INTO users (username, password) VALUES (?, ?)"
        query_db(query_str, (username, password_hashed))
        return jsonify({
            "status": True
        })

@app.route("/login", methods=accepted_methods)
def login():
    username = request.json.get("username", "")
    password = request.json.get("password", "")

    if bcrypt.check_password_hash(get_password(username), password):
        session["username"] = username
        return jsonify({
            "status": True
        })
    else:
        return jsonify({
            "status": False
        })

@app.route("/secret_page", methods=accepted_methods)
@login_required
def secret_page():
    return "I'm here"

@app.route("/logout", methods=accepted_methods)
def logout():
    session.pop("username", None)
    return redirect(url_for("home_page"))


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()
