CREATE TABLE Users (
    username TEXT UNIQUE,
    password TEXT
);

CREATE TABLE Groups (
    GroupName TEXT UNIQUE
);

CREATE TABLE UserGroups (
    UserID INTEGER,
    GroupID INTEGER,
    Permission INTEGER,
    FOREIGN KEY(UserID) REFERENCES Users(ROWID) ON DELETE CASCADE,
    FOREIGN KEY(GroupID) REFERENCES Groups(ROWID) ON DELETE CASCADE
);

CREATE TABLE TaskGroups (
    TaskID INTEGER UNIQUE,
    GroupID INTEGER,
    FOREIGN KEY(TaskID) REFERENCES Tasks(ROWID) ON DELETE CASCADE,
    FOREIGN KEY(GroupID) REFERENCES Groups(ROWID) ON DELETE CASCADE
);

CREATE TABLE Tasks (
    AuthorID INTEGER,
    Title TEXT,
    Difficulty INTEGER,
    Transcript TEXT,
    GradingTranscript TEXT,
    AudioLink TEXT,
    AudioFilePath TEXT,
    AudioTimeBegin INTEGER,
    AudioTimeEnd INTEGER,
    CurrentStatus INTEGER,
    Source TEXT,
    FOREIGN KEY(AuthorID) REFERENCES Users(ROWID) ON DELETE CASCADE
);

CREATE TABLE Submissions (
    UserID INTEGER,
    TaskID INTEGER,
    SubmissionFilePath TEXT,
    CurrentStatus INTEGER,
    Transcript TEXT,
    Score REAL,
    FOREIGN KEY (UserID) REFERENCES Users(ROWID) ON DELETE CASCADE,
    FOREIGN KEY (TaskID) REFERENCES Tasks(ROWID) ON DELETE CASCADE
);

INSERT INTO Groups (GroupName) VALUES ("Everyone");