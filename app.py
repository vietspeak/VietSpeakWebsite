import sqlite3
import json
from flask import Flask, render_template, request, g
from flask.json import jsonify

constant_data = None
with open("constant.json", "r") as f:
    constant_data = json.load(f) 
DATABASE = constant_data["PATH_TO_DATABASE"]
app = Flask(__name__)
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
    cur.close()
    return (rv[0] if rv else None) if one else rv


@app.route("/")
def home_page():
    return render_template("index.html")

@app.route("/register", methods=accepted_methods)
def register():
    username = request.json.get("username", "")
    password = request.json.get("password", "")
    
    return jsonify({
        "username": username,
        "password": password,
        "status": ""
    })


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()
