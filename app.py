import re
import sqlite3
import json
import time
import io
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

def get_password(username):
    query_str = "SELECT password FROM users WHERE username = ?"
    r = query_db(query_str, (username, ))
    if len(r) == 0:
        return None
    else:
        return r[0]["password"]

def get_user_id(username):
    query_str = "SELECT ROWID FROM users WHERE username = ?"
    r = query_db(query_str, (username, ))
    if len(r) == 0:
        return None
    else:
        return r[0]["ROWID"]

def get_group_id(groupname):
    query_str = "SELECT ROWID FROM groups WHERE GroupName = ?"
    r = query_db(query_str, (groupname, ))
    if len(r) == 0:
        return None
    else:
        return r[0]["ROWID"]

def is_user_in_group(user_id, group_id):
    query_str = """
        SELECT * FROM UserGroups
        WHERE UserID = ? AND GroupID = ? AND IsMember = 1
    """

    r = query_db(query_str, (user_id, group_id))

    return len(r) == 1

def is_user_can_change_member(user_id, group_id):
    query_str = """
        SELECT * FROM UserGroups
        WHERE UserID = ? AND GroupID = ? AND CanChangeMember = 1
    """

    r = query_db(query_str, (user_id, group_id))

    return len(r) == 1

def is_user_invited(user_id, group_id):
    query_str = """
        SELECT * FROM UserGroups
        WHERE UserID = ? AND GroupID = ? AND IsInvited = 1
    """

    r = query_db(query_str, (user_id, group_id))

    return len(r) == 1

def get_group_name(group_id):
    query_str = """
        SELECT * FROM Groups
        WHERE ROWID = ?    
    """

    r = query_db(query_str, (group_id, ))

    if len(r) == 0:
        return None
    else:
        return r[0]["GroupName"]


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect(url_for("home_page"))
        return f(*args, **kwargs)
    
    return decorated_function

@app.route("/")
def home_page():
    return render_template("index.html")



@app.route("/register", methods=accepted_methods)
def register():
    username = request.values.get("username", "")
    password = request.values.get("password", "")

    if password == "":
        return jsonify({
            "status": False,
            "message": "The password cannot be empty."
        })
    
    password_hashed = bcrypt.generate_password_hash(password).decode('utf-8')

    if get_password(username) is not None:
        return jsonify({
            "status": False,
            "message": "This username has already been taken"
        })
    else:
        query_str = "INSERT INTO users (username, password) VALUES (?, ?)"
        query_db(query_str, (username, password_hashed))

        user_id = get_user_id(username)
        group_id = get_group_id("Everyone")

        query_str = "INSERT INTO UserGroups (UserID, GroupID, IsMember) VALUES (?, ?, ?)"
        query_db(query_str, (user_id, group_id, 1))

        session["user_id"] = user_id
        session["username"] = username
        return jsonify({
            "status": True
        })

@app.route("/login", methods=accepted_methods)
def login():
    username = request.values.get("username", "")
    password = request.values.get("password", "")

    actual_password = get_password(username)

    if actual_password is not None and bcrypt.check_password_hash(actual_password, password):
        session["username"] = username
        session["user_id"] = get_user_id(username)
        return jsonify({
            "status": True
        })
    else:
        return jsonify({
            "status": False
        })

@app.route("/tasks", methods=accepted_methods)
@login_required
def tasks():
    username = session.get("username")
    return render_template("tasks.html", username=username)

@app.route("/create_task_page", methods=accepted_methods)
@login_required
def create_task_page():
    username = session.get("username")
    return render_template("create_task.html", username=username)

@app.route("/get_groups", methods=accepted_methods)
@login_required
def get_groups():
    username = session.get("username")
    
    query = """
        SELECT Groups.ROWID AS id, Groups.GroupName as name 
        FROM Groups, Users, UserGroups WHERE
        Users.username = ? AND Users.ROWID = UserGroups.UserID AND UserGroups.GroupID = Groups.ROWID AND UserGroups.IsMember = 1
    """

    r = query_db(query, (username, ))

    result_array = []
    for x in r:
        result_array.append({"id": x["id"], "name": x["name"]})
    
    return jsonify({"result": result_array})

@app.route("/create_group_page", methods=accepted_methods)
@login_required
def create_group_page():
    username = session.get("username")
    return render_template("create_group.html", username = username)


@app.route("/create_group", methods=accepted_methods)
@login_required
def create_group():
    user_id = session.get("user_id")
    group_name = request.values.get("group_name", "")

    if get_group_id(group_name) is None:
        query_str = "INSERT INTO Groups (GroupName) VALUES (?)"
        query_db(query_str, (group_name, ))

        query_str = "INSERT INTO UserGroups (UserId, GroupId, IsMember, IsOwner, CanChangeMember, CanChangeTask) VALUES (?, ?, ?, ?, ?, ?)"
        query_db(query_str, (user_id, get_group_id(group_name), 1, 1, 1, 1))

        return jsonify({
            "status": True
        })
    else:
        return jsonify({
            "status": False
        })

@app.route("/get_members_in_group", methods=accepted_methods)
@login_required
def get_members_in_group():
    user_id = session.get("user_id")
    group_id = int(request.values.get("group_id"))

    if not is_user_in_group(user_id, group_id):
        return {
            "result": []
        }
    
    query_str = """
        SELECT Users.ROWID as id, Users.username as name
        FROM Users, UserGroups
        WHERE UserGroups.GroupID = ? AND UserGroups.UserID = Users.ROWID AND UserGroups.IsMember = 1
    """

    r = query_db(query_str, (group_id, ))

    total_array = []
    for x in r:
        total_array.append({
            "id": x["id"],
            "name": x["name"]
        })
    
    return {
        "result": total_array
    }

@app.route("/get_invitations", methods=accepted_methods)
@login_required
def get_invitations():
    user_id = session.get("user_id")
    
    query_str = """
        SELECT UserGroups.GroupID as id, Groups.GroupName as name
        FROM UserGroups, Groups
        WHERE UserGroups.UserID = ? AND UserGroups.GroupID = Groups.ROWID AND UserGroups.IsInvited = 1
    """

    r = query_db(query_str, (user_id, ))

    total_array = []
    for x in r:
        total_array.append({
            "id": x["id"],
            "name": x["name"]
        })
    
    return {
        "result": total_array
    }

@app.route("/accept_invitation", methods=accepted_methods)
@login_required
def accept_invitation():
    user_id = session.get("user_id")
    group_id = int(request.values.get("id"))
    query_str = """
        UPDATE UserGroups
        SET IsInvited = 0, IsMember = 1
        WHERE UserID = ? AND GroupID = ? AND IsInvited = 1
    """

    query_db(query_str, (user_id, group_id))

    return {
        "status": True
    }


@app.route("/view_group", methods=accepted_methods)
@login_required
def view_group():
    user_id = session.get("user_id")
    group_id = int(request.values.get("id"))

    if not is_user_in_group(user_id, group_id):
        return redirect(url_for("logout"))
    
    return render_template("view_group.html", 
                            username = session.get("username"), 
                            groupname = get_group_name(group_id), 
                            group_id = group_id)

@app.route("/invite_member", methods=accepted_methods)
@login_required
def invite_member():
    owner_id = session.get("user_id")
    invited_member_name = request.values.get("username")
    invited_id = get_user_id(invited_member_name)

    if invited_id is None:
        return jsonify({
            "status": False
        })
    
    group_id = int(request.values.get("group_id"))

    if not is_user_can_change_member(owner_id, group_id):
        return redirect(url_for("logout"))

    if is_user_invited(invited_id, group_id):
        return jsonify({
            "status": True
        })
    
    query_str = """
        INSERT INTO UserGroups (UserID, GroupID, IsInvited) VALUES (?, ?, 1)
    """

    query_db(query_str, (invited_id, group_id))

    return jsonify({
        "status": True
    })

    
@app.route("/logout", methods=accepted_methods)
def logout():
    session.pop("username", None)
    return redirect(url_for("home_page"))


@app.route("/create_task", methods=accepted_methods)
def create_task():
    return jsonify({
        "status": False
    })

@app.route("/upload_file", methods=accepted_methods)
def upload_file():
    file = request.files.get("file", "")
    fake_file = io.BytesIO()
    file.save(fake_file)

    query_str = """
        INSERT INTO AudioFiles (AudioFile) VALUES (?)
    """

    query_db(query_str, (fake_file.getvalue(), ))

    query_str = """
        SELECT last_insert_rowid() as id FROM AudioFiles
    """

    r = query_db(query_str)

    return jsonify({
        "file_id": r[0]["id"],
        "status": True
    })


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()
