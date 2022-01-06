CREATE TABLE Users (
    username TEXT UNIQUE,
    password TEXT
);

CREATE TABLE Groups (
    GroupName TEXT UNIQUE,
    CreationTime REAL DEFAULT ((julianday('now') - 2440587.5)*86400.0)
);

CREATE TABLE UserGroups (
    UserID INTEGER,
    GroupID INTEGER,
    IsInvited INTEGER DEFAULT 0,
    IsMember INTEGER DEFAULT 0,
    IsOwner INTEGER DEFAULT 0,
    CanChangeMember INTEGER DEFAULT 0,
    CanChangeTask INTEGER DEFAULT 0,
    CreationTime REAL DEFAULT ((julianday('now') - 2440587.5)*86400.0),
    UNIQUE(UserID, GroupID),
    FOREIGN KEY(UserID) REFERENCES Users(ROWID) ON DELETE CASCADE,
    FOREIGN KEY(GroupID) REFERENCES Groups(ROWID) ON DELETE CASCADE
);

CREATE TABLE TaskGroups (
    TaskID INTEGER UNIQUE,
    GroupID INTEGER,
    FOREIGN KEY(TaskID) REFERENCES Tasks(ROWID) ON DELETE CASCADE,
    FOREIGN KEY(GroupID) REFERENCES Groups(ROWID) ON DELETE CASCADE
);

CREATE TABLE AudioFiles (
    AudioFile BLOB,
    Transcript TEXT
);

CREATE TABLE Tasks (
    AuthorID INTEGER,
    Title TEXT,
    Difficulty INTEGER,
    Transcript TEXT,
    FileID INTEGER
    AudioLink TEXT,
    AudioTimeBegin INTEGER,
    AudioTimeEnd INTEGER,
    CurrentStatus INTEGER,
    CreationTime REAL DEFAULT ((julianday('now') - 2440587.5)*86400.0),
    LastUpdated REAL DEFAULT ((julianday('now') - 2440587.5)*86400.0),
    Source TEXT,
    FOREIGN KEY(AuthorID) REFERENCES Users(ROWID) ON DELETE CASCADE,
    FOREIGN KEY(FileID) REFERENCES AudioFile(ROWID) ON DELETE CASCADE
);

CREATE TABLE Submissions (
    UserID INTEGER,
    TaskID INTEGER,
    FileID INTEGER
    CurrentStatus INTEGER,
    Transcript TEXT,
    Score REAL,
    CreationTime REAL DEFAULT ((julianday('now') - 2440587.5)*86400.0),
    FOREIGN KEY(FileID) REFERENCES AudioFile(ROWID) ON DELETE CASCADE
    FOREIGN KEY (UserID) REFERENCES Users(ROWID) ON DELETE CASCADE,
    FOREIGN KEY (TaskID) REFERENCES Tasks(ROWID) ON DELETE CASCADE
);

INSERT INTO Groups (GroupName) VALUES ("Everyone");