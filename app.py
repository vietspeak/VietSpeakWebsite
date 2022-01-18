import sqlite3
import json
import io
import eng_to_ipa as ipa
from functools import wraps
from flask import Flask, render_template, request, g, session, redirect, url_for
from flask.json import jsonify
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

constant_data = None
with open("constant.json", "r") as f:
    constant_data = json.load(f) 
DATABASE = constant_data["PATH_TO_DATABASE"]

app = Flask(__name__)
app.secret_key = constant_data["SESSION_SECRET_KEY"]
app.config['MAX_CONTENT_LENGTH'] = constant_data["MAX_CONTENT_LENGTH"]
bcrypt = Bcrypt(app)
accepted_methods = ["POST", "GET"]

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

def to_int(s):
    try:
        return int(s)
    except ValueError:
        return 0

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

def can_user_change_member(user_id, group_id):
    query_str = """
        SELECT * FROM UserGroups
        WHERE UserID = ? AND GroupID = ? AND CanChangeMember = 1
    """

    r = query_db(query_str, (user_id, group_id))

    return len(r) == 1

def can_user_change_task(user_id, group_id):
    query_str = """
        SELECT * FROM UserGroups
        WHERE UserID = ? AND GroupID = ? AND CanChangeTask = 1
    """
    r = query_db(query_str, (user_id, group_id))
    return len(r) == 1

def is_user_author_task(user_id, task_id):
    query_str = """
        SELECT * FROM Tasks
        WHERE AuthorID = ? AND ROWID = ?
    """

    r = query_db(query_str, (user_id, task_id), one=True)

    return r is not None

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

def can_user_access_task(user_id, task_id):
    query_str = """
        SELECT ROWID as id
        FROM Tasks
        WHERE ROWID = ? AND (
            AuthorID = ? OR
            AuthorID IN (
                SELECT UserGroups.UserID as AuthorID
                FROM UserGroups, TaskGroups
                WHERE TaskGroups.GroupID = UserGroups.GroupID AND TaskGroups.TaskID = ? AND UserGroups.IsMember = 1
            )
        )
    """

    r = query_db(query_str, (task_id, user_id, task_id), True)

    return r is not None


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
@limiter.limit("10 per day")
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

    session.pop("groupname", None)
    session.pop("group_id", None)

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
@limiter.limit("10 per day")
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

@app.route("/search_members_in_group", methods=accepted_methods)
@login_required
def search_members_in_group():
    user_id = session.get("user_id")
    group_id = session.get("group_id")
    name = request.values.get("username", "")
    offset = request.values.get("offset", 0)

    if not is_user_in_group(user_id, group_id):
        return {
            "result": []
        }
    
    query_str = """
        SELECT Users.ROWID as id, Users.username as name, UserGroups.CanChangeMember as can_change_member, UserGroups.CanChangeTask as can_change_task
        FROM Users, UserGroups
        WHERE UserGroups.GroupID = ? AND UserGroups.UserID = Users.ROWID AND UserGroups.IsMember = 1 AND Users.username LIKE ?
        LIMIT ?, 10
    """

    r = query_db(query_str, (group_id, "%" + name + "%", offset))

    total_array = []
    for x in r:
        total_array.append({
            "id": x["id"],
            "name": x["name"],
            "can_change_member": x["can_change_member"],
            "can_change_task": x["can_change_task"]
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

@app.route("/invite_member", methods=accepted_methods)
@limiter.limit("1000 per day")
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

    if not can_user_change_member(owner_id, group_id):
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
    session.pop("user_id", None)
    session.pop("group_id", None)
    session.pop("groupname", None)
    return redirect(url_for("home_page"))


@app.route("/create_task", methods=accepted_methods)
@limiter.limit("200 per day")
@login_required
def create_task():
    
    author_id = session.get("user_id")
    title = request.values.get("title", "")
    transcript = request.values.get("transcript", "")
    file = request.files.get("audio_file", None)

    audio_link = request.values.get("audio_link", "")
    audio_time_begin = to_int(request.values.get("audio_time_begin", 0))
    audio_time_end = to_int(request.values.get("audio_time_end", 0))
    number_of_syllables = ipa.syllable_count(transcript)

    if isinstance(number_of_syllables, list):
        number_of_syllables = sum(number_of_syllables)

    source = request.values.get("source", "")

    if title == "" or transcript == "" or file is None:
        return jsonify({
            "status": False,
            "message": "The title/transcript/audio file is not provided."
        })

    query_str = """
        INSERT INTO AudioFiles (AudioFile) VALUES (?)
    """

    fake_file = io.BytesIO()
    file.save(fake_file)
    query_db(query_str, (fake_file.getvalue(), ))

    query_str = """
        SELECT last_insert_rowid() as id FROM AudioFiles
    """

    file_id = query_db(query_str)[0]["id"]

    query_str = """
        INSERT INTO Tasks (AuthorID, Title, Transcript, FileID, AudioLink, AudioTimeBegin, AudioTimeEnd, NumberOfSyllables, CurrentStatus, Source)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """

    query_db(query_str, (author_id, title, transcript, file_id, audio_link, audio_time_begin, audio_time_end, number_of_syllables, 0, source))

    return jsonify({
        "status": True,
    })

@app.route("/search_tasks_created_by_user", methods=accepted_methods)
@login_required
def search_tasks_created_by_user():
    user_id = session.get("user_id")

    title = request.values.get("title", "")
    source = request.values.get("source", "")
    offset = request.values.get("offset", 0)
    query_str = """
        SELECT ROWID as id, Title as title, Source as source
        FROM Tasks
        WHERE AuthorID = ? AND Title LIKE ? AND Source LIKE ?
        LIMIT ?, 10
    """

    r = query_db(query_str, (user_id, "%" + title + "%", "%" + source + "%", offset))

    total_array = []
    for x in r:
        total_array.append({"id": x["id"], "title": x["title"], "source": x["source"]})
    
    return jsonify({
        "result": total_array
    })

@app.route("/search_tasks_in_group", methods=accepted_methods)
@login_required
def search_tasks_in_group():
    user_id = session.get("user_id")
    group_id = session.get("group_id")

    if not is_user_in_group(user_id, group_id):
        return redirect(url_for("logout"))
    

    title = request.values.get("title", "")
    source = request.values.get("source", "")
    offset = request.values.get("offset", 0)

    query_str = """
        SELECT Tasks.ROWID as id, Tasks.Title as title, Tasks.Source as source
        FROM Tasks, TaskGroups
        WHERE Tasks.ROWID = TaskGroups.TaskID AND TaskGroups.GroupID = ? AND Tasks.Title LIKE ? AND Tasks.Source LIKE ?
        LIMIT ?, 10
    """

    r = query_db(query_str, (group_id, "%" + title + "%", "%" + source + "%", offset))

    total_array = []
    for x in r:
        total_array.append({"id": x["id"], "title": x["title"], "source": x["source"] })
    
    return jsonify({
        "result": total_array
    })

@app.route("/get_task", methods=accepted_methods)
@login_required
def get_task():
    user_id = session.get("user_id")

    task_id = to_int(request.values.get("task_id", ""))

    query_str = """
        SELECT ROWID as id, Title, Transcript, AudioLink, AudioTimeBegin, AudioTimeEnd, Source
        FROM Tasks
        WHERE ROWID = ? AND (
            AuthorID = ? OR
            AuthorID IN (
                SELECT UserGroups.UserID as AuthorID
                FROM UserGroups, TaskGroups
                WHERE TaskGroups.GroupID = UserGroups.GroupID AND TaskGroups.TaskID = ? AND UserGroups.IsMember = 1
            )
        )
    """

    r = query_db(query_str, (task_id, user_id, task_id), True)

    if r is None:
        return jsonify({
            "status": False
        })
    
    return jsonify({
        "status": True,
        "id": r["id"],
        "title": r["Title"],
        "transcript": r["Transcript"],
        "audio_link": r["AudioLink"],
        "start_time": r["AudioTimeBegin"],
        "end_time": r["AudioTimeEnd"],
        "source": r["Source"]
    })

@app.route("/view_task", methods=accepted_methods)
@login_required
def view_task():
    task_id = to_int(request.values.get("id"))
    username = session.get("username", "")
    user_id = session.get("user_id")

    return render_template("view_task.html", 
                           username=username, 
                           task_id=task_id, 
                           user_is_author = is_user_author_task(user_id, task_id),
                           groupname = session.get("groupname", None),
                           group_id = session.get("group_id", None))

@app.route("/update_task", methods=accepted_methods)
@login_required
def update_task():
    user_id = session.get("user_id")
    task_id = to_int(request.values.get("task_id"))
    title = request.values.get("title", "")
    transcript = request.values.get("transcript", "")
    file = request.files.get("audio_file", None)
    audio_link = request.values.get("audio_link", "")
    audio_time_begin = to_int(request.values.get("audio_time_begin", 0))
    audio_time_end = to_int(request.values.get("audio_time_end", 0))
    number_of_syllables = ipa.syllable_count(transcript)

    if isinstance(number_of_syllables, list):
        number_of_syllables = sum(number_of_syllables)

    source = request.values.get("source", "")


    if not can_user_access_task(user_id, task_id):
        return redirect(url_for("logout"))
    

    if title == "" or transcript == "":
        return jsonify({
            "status": False,
            "message": "The title/transcript is not provided."
        })

    
    if file is not None:
        query_str = """
            INSERT INTO AudioFiles (AudioFile) VALUES (?)
        """

        fake_file = io.BytesIO()
        file.save(fake_file)
        query_db(query_str, (fake_file.getvalue(), ))

        query_str = """
            SELECT last_insert_rowid() as id FROM AudioFiles
        """

        file_id = query_db(query_str)[0]["id"]

        query_str = """
            UPDATE Tasks
            SET FileID = ?, CurrentStatus = 1
            WHERE ROWID = ?
        """

        query_db(query_str, (file_id, task_id))

    
    query_str = """
        UPDATE Tasks
        SET Title = ?, Transcript = ?, AudioLink = ?, AudioTimeBegin = ?, AudioTimeEnd = ?, NumberOfSyllables = ?, Source = ?
        WHERE ROWID = ?
    """

    query_db(query_str, (title, transcript, audio_link, audio_time_begin, audio_time_end, number_of_syllables, source, task_id))

    return jsonify({
        "status": True,
    })

def upload_file(file):
    fake_file = io.BytesIO()
    file.save(fake_file)

    query_str = """
        INSERT INTO AudioFiles (AudioFile) VALUES (?)
    """
    query_db(query_str, (fake_file.getvalue(), ))
    query_str = """
        SELECT last_insert_rowid() as id FROM AudioFiles
    """
    r = query_db(query_str, one=True)
    return r["id"]

@app.route("/submit", methods=accepted_methods)
@limiter.limit("200 per day")
@login_required
def submit():
    user_id = session.get("user_id")
    task_id = to_int(request.values.get("task_id", ""))
    if not can_user_access_task(user_id, task_id):
        return redirect(url_for("logout"))
    
    file = request.files.get("audio_file", None)

    if file is None:
        return jsonify({
            "status": False,
        })
    
    file_id = upload_file(file)

    query_str = """
        INSERT INTO Submissions (UserID, TaskID, FileID, CurrentStatus)
        VALUES (?, ?, ?, ?)
    """

    query_db(query_str, (user_id, task_id, file_id, 1))

    return jsonify({
        "status": True
    })

@app.route("/get_submissions", methods=accepted_methods)
@login_required
def get_submissions():
    user_id = session.get("user_id")
    task_id = int(request.values.get("task_id"))

    if not can_user_access_task(user_id, task_id):
        return redirect(url_for("logout"))
    
    query_str = """
        SELECT ROWID as id, CreationTime as time, CurrentStatus as status, Score as score
        FROM Submissions
        WHERE UserID = ? AND TaskID = ?
        ORDER BY CreationTime DESC
        LIMIT 5
    """

    r = query_db(query_str, (user_id, task_id))

    total_array = []
    for x in r:
        total_array.append({
            "id": x["id"],
            "time": x["time"],
            "status": x["status"],
            "score": round(x["score"] if x["score"] is not None else 0, 2)
        })
    
    return jsonify({
        "result": total_array
    })

@app.route("/get_submission", methods=accepted_methods)
@login_required
def get_submission():
    user_id = session.get("user_id")
    submission_id = int(request.values.get("id"))

    query_str = """
        SELECT Tasks.ROWID as task_id, 
               Tasks.Title as task_title, 
               Submissions.CurrentStatus as status, 
               Submissions.Score as score, 
               Submissions.CreationTime as time,
               Submissions.Feedback as feedback,
               AudioFiles.transcript as transcript
        FROM Submissions, Tasks, AudioFiles
        WHERE Submissions.ROWID = ? AND Submissions.UserID = ? AND Submissions.TaskID = Tasks.ROWID AND AudioFiles.ROWID = Submissions.FileID
    """


    x = query_db(query_str, (submission_id, user_id), one=True)
    if x is None:
        return redirect(url_for("logout"))
    
    
    return jsonify({
        "id": submission_id,
        "time": x["time"],
        "status": x["status"],
        "score": round(x["score"], 2),
        "feedback": x["feedback"],
        "task_id": x["task_id"],
        "task_title": x["task_title"],
        "transcript": x["transcript"]
    })

@app.route("/view_submission", methods=accepted_methods)
@login_required
def view_submission():
    username = session.get("username")

    group_id = session.get("group_id", None)
    groupname = session.get("groupname", None)


    submission_id = int(request.values.get("id"))


    return render_template("view_submission.html",
                           username = username,
                           group_id = group_id,
                           groupname = groupname,
                           submission_id = submission_id)

    
@app.route("/add_task_to_group", methods=accepted_methods)
@limiter.limit("200 per day")
@login_required
def add_task_to_group():
    user_id = session.get("user_id")
    group_id = to_int(request.values.get("group_id", ""))
    task_title = request.values.get("task_title", "")

    if not can_user_change_task(user_id, group_id):
        return redirect(url_for("logout"))

    query_str = """
        SELECT ROWID as id
        FROM Tasks
        WHERE AuthorID = ? AND Title = ?
    """

    r = query_db(query_str, (user_id, task_title, ), one=True)

    if r is None:
        print("I'm here")
        return jsonify({
            "status": False,
            "message": "You do not have any task with this title."
        })
    
    task_id = r["id"]

    query_str = """
        SELECT * FROM TaskGroups WHERE TaskID = ? AND GroupID = ?
    """

    r = query_db(query_str, (task_id, group_id), one=True)

    if r is not None:
        return jsonify({
            "status": True
        })
    
    query_str = """
        INSERT INTO TaskGroups (TaskID, GroupID)
        VALUES (?, ?)
    """


    query_db(query_str, (task_id, group_id))

    return jsonify({
        "status": True
    })

@app.route("/view_group_members", methods=accepted_methods)
@login_required
def view_group_members():
    user_id = session.get("user_id")
    group_id = int(request.values.get("id"))

    can_change_member = can_user_change_member(user_id, group_id)

    if not is_user_in_group(user_id, group_id):
        return redirect(url_for("logout"))
    
    session["group_id"] = group_id
    session["groupname"] = get_group_name(group_id)
    
    return render_template("view_group_members.html", 
                            username = session.get("username"), 
                            groupname = session.get("groupname"), 
                            group_id = group_id,
                            can_change_member = can_change_member)

@app.route("/change_group_member_rights", methods=accepted_methods)
@limiter.limit("1000 per day")
@login_required
def change_group_member_rights():
    user_id = session.get("user_id")
    group_id = session.get("group_id")
    group_member_id = int(request.values.get("user_id", 0))

    if group_member_id == user_id:
        return jsonify({
            "status": False,
            "message": "You cannot change your rights. Please contact someone else."
        })
    
    group_member_change_task = request.values.get("can_change_task", None)
    group_member_change_members = request.values.get("can_change_member", None)

    can_change_member = can_user_change_member(user_id, group_id)

    if not (is_user_in_group(user_id, group_id) and is_user_in_group(group_member_id, group_id) and can_change_member):
        return redirect(url_for("logout"))
    

    if group_member_change_task is not None:
        group_member_change_task = 1 if group_member_change_task == "true" else 0
        query_str = """
            UPDATE UserGroups
            SET CanChangeTask = ?
            WHERE UserID = ? AND GroupID = ?
        """
        query_db(query_str, (group_member_change_task, group_member_id, group_id))

    if group_member_change_members is not None:
        group_member_change_members = 1 if group_member_change_members == "true" else 0
        query_str = """
            UPDATE UserGroups
            SET CanChangeMember = ?
            WHERE UserID = ? AND GroupID = ?
        """
        query_db(query_str, (group_member_change_members, group_member_id, group_id))

    return jsonify({
        "status": True
    })

@app.route("/get_invited_members", methods=accepted_methods)
@login_required
def get_invited_members():
    user_id = session.get("user_id")
    group_id = session.get("group_id")

    if not is_user_in_group(user_id, group_id):
        return redirect(url_for("logout"))
    
    query_str = """
        SELECT Users.ROWID as id, Users.username as name
        FROM Users, UserGroups
        WHERE Users.ROWID = UserGroups.UserID AND UserGroups.IsInvited = 1
    """

    r = query_db(query_str)

    total = []
    for x in r:
        total.append({
            "id": x["id"],
            "name": x["name"]
        })
    
    return jsonify({
        "result": total
    })

@app.route("/view_group_tasks", methods=accepted_methods)
@login_required
def view_group_tasks():
    user_id = session.get("user_id")
    group_id = int(request.values.get("id"))

    can_change_task = can_user_change_task(user_id, group_id)

    if not is_user_in_group(user_id, group_id):
        return redirect(url_for("logout"))
    
    session["group_id"] = group_id
    session["groupname"] = get_group_name(group_id)
    
    return render_template("view_group_tasks.html", 
                            username = session.get("username"), 
                            groupname = session.get("groupname"), 
                            group_id = group_id,
                            can_change_task = can_change_task)


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()
