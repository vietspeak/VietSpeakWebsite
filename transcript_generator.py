from vosk import Model, KaldiRecognizer, SetLogLevel
import os
import subprocess
import json
import sqlite3
from audio_grader import grader

constant_data = None
with open("constant.json", "r") as f:
    constant_data = json.load(f) 
DATABASE = constant_data["PATH_TO_DATABASE"]

SetLogLevel(0)
sample_rate=16000
model = Model("model")
rec = KaldiRecognizer(model, sample_rate)

def speech_to_text(filename = "input.mp3"):
    process = subprocess.Popen(['ffmpeg', '-loglevel', 'quiet', '-i',
                            filename,
                            '-ar', str(sample_rate) , '-ac', '1', '-f', 's16le', '-'],
                            stdout=subprocess.PIPE)

    ret = ""
    while True:
        data = process.stdout.read(4000)
        if len(data) == 0:
            break
        if rec.AcceptWaveform(data):
            res = rec.Result()
            ret += json.loads(res)["text"] + " "

    ret += json.loads(rec.FinalResult())["text"]
    return ret

while True:
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row

    def query_db(query, args=(), one=False):
        cur = db.execute(query, args)
        rv = cur.fetchall()
        db.commit()
        return (rv[0] if rv else None) if one else rv


    query_str = """
        SELECT ROWID as id, AudioFile as file
        FROM AudioFiles
        WHERE Transcript IS NULL
        LIMIT 1
    """

    r = query_db(query_str)

    if len(r) == 0:
        db.close()
        continue

    file_id = r[0]["id"]

    with open("input.in", "wb") as f:
        f.write(r[0]["file"])
    os.system("ffmpeg -y -i input.in output.mp3")

    transcript = speech_to_text("output.mp3")

    query_str = """
        UPDATE AudioFiles
        SET AudioFile = ?, Transcript = ?
        WHERE ROWID = ?
    """

    query_db(query_str, (None, transcript, file_id))


    query_str = """
        SELECT ROWID as id, Transcript as transcript FROM Tasks
        WHERE FileID = ?
    """

    r = query_db(query_str, (file_id, ), one=True)

    if r is not None:
        task_id = r["id"]
        actual_transcript = r["transcript"].lower().split(" ")
        transcript = transcript.lower()
        actual_transcript = " ".join(filter(lambda x: x in transcript, actual_transcript))
        query_str = """
            UPDATE AudioFiles
            SET Transcript = ?
            WHERE ROWID = ?
        """
        query_db(query_str, (actual_transcript, file_id))
        query_str = """
            UPDATE Tasks
            SET CurrentStatus = 2
            WHERE ROWID = ?
        """
        query_db(query_str, (task_id, ))
    
    query_str = """
        SELECT ROWID as id, TaskID FROM Submissions
        WHERE FileID = ?
    """

    r = query_db(query_str, (file_id, ), one=True)

    if r is not None:
        submission_id = r["id"]
        task_id = r["TaskID"]

        query_str = """
            SELECT AudioFiles.Transcript as Transcript
            FROM AudioFiles, Tasks
            WHERE Tasks.CurrentStatus = 2 AND Tasks.FileID = AudioFiles.ROWID AND Tasks.ROWID = ?
        """

        r2 = query_db(query_str, (task_id, ), one=True)

        feedback = ""
        score = 0

        if r2 is None:
            feedback = "Judge Error. Please resubmit."
            score = 0
        else:
            actual_transcript = r2["Transcript"]
            score, mismatches = grader(actual_transcript, transcript)
            feedback = []
            for m in mismatches:
                if m[1] == "":
                    feedback.append("*{}* -> ∅".format(m[0]))
                else:
                    feedback.append("*{}* -> `{}`".format(m[0], m[1]))
            feedback = " | ".join(feedback)

        query_str = """
            UPDATE Submissions
            SET Feedback = ?, Score = ?, CurrentStatus = 2
            WHERE ROWID = ?
        """

        query_db(query_str, (feedback, score, submission_id))
    
    db.close()
    