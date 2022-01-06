from vosk import Model, KaldiRecognizer, SetLogLevel
import os
import subprocess
import json
import sqlite3

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

    if len(r) != 0:
        with open("input.in", "wb") as f:
            f.write(r[0]["file"])
        os.system("ffmpeg -y -i input.in output.mp3")

        transcript = speech_to_text("output.mp3")

        query_str = """
            UPDATE AudioFiles
            SET AudioFile = ?, Transcript = ?
            WHERE ROWID = ?
        """

        query_db(query_str, (None, transcript, r[0]["id"]))
    
    db.close()
    