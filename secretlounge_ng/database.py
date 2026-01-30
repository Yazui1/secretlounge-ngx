import logging
import os
import json
import sqlite3
from datetime import date, datetime, timedelta, timezone
from threading import RLock
from typing import Optional, Generator

from .globals import *

# what's inside the database


class SystemConfig():
    def __init__(self):
        self.motd = None
        self.privacy = None

    def defaults(self):
        self.motd = ""
        self.privacy = ""


USER_PROPS = (
    "id", "username", "realname", "rank", "joined", "left", "lastActive",
    "cooldownUntil", "blacklistReason", "warnings", "warnExpiry", "karma",
    "hideKarma", "debugEnabled", "tripcode", "sendconfirm", "votebutton",
    "signenabled", "tsignenabled", "credits", "creditsMessageCount", "creditsMediaCount",
    "creditsLastTax", "creditsEarnedToday", "creditsLastEarnReset"
)

ID_ALPHA = "0123456789abcdefghijklmnopqrstuv"


class User():
    __slots__ = USER_PROPS
    global_salt = b""

    id: int
    username: Optional[str]
    realname: str
    rank: int
    joined: datetime
    left: Optional[datetime]
    lastActive: datetime
    cooldownUntil: Optional[datetime]
    blacklistReason: Optional[str]
    warnings: int
    warnExpiry: Optional[datetime]
    karma: int
    hideKarma: bool
    debugEnabled: bool
    tripcode: Optional[str]
    sendconfirm: bool
    votebutton: bool
    signenabled: bool
    tsignenabled: bool
    credits: float
    creditsMessageCount: int
    creditsMediaCount: int
    creditsLastTax: Optional[datetime]
    creditsEarnedToday: float
    creditsLastEarnReset: Optional[datetime]

    @staticmethod
    def setSalt(salt):
        assert all(isinstance(v, int) for v in salt)
        User.global_salt = salt

    def __init__(self):
        for k in USER_PROPS:
            setattr(self, k, None)

    def __eq__(self, other):
        if isinstance(other, User):
            return self.id == other.id
        return NotImplemented

    def __str__(self):
        return "<User id=%d aka %r>" % (self.id, self.getFormattedName())

    def defaults(self):
        self.rank = RANKS.user
        self.joined = datetime.now()
        self.lastActive = self.joined
        self.warnings = 0
        self.karma = 0
        self.hideKarma = False
        self.debugEnabled = False

        # whether to ask for confirmation when custom filter returns QUESTION
        # True = show confirmation button (default behaviour), False = bypass
        self.sendconfirm = True

        # whether to show vote/delete button on received messages
        # True = recipients see vote button (default), False = hidden
        self.votebutton = True

        # whether to auto-sign all messages (as if using /s)
        # True = auto-sign enabled, False = disabled (default)
        self.signenabled = False

        # whether to auto-tripcode all messages (as if using /t)
        # True = auto-tripcode enabled, False = disabled (default)
        self.tsignenabled = False

        # Credit system
        self.credits = 20.0  # Starting credits (configurable via config)
        self.creditsMessageCount = 0  # Counter for messages towards earning credits
        self.creditsMediaCount = 0  # Counter for media towards earning credits
        self.creditsLastTax = datetime.now()  # Last time daily tax was applied
        self.creditsEarnedToday = 0.0  # Credits earned today (for daily cap)
        self.creditsLastEarnReset = datetime.now()  # Last time daily earn was reset

    def isJoined(self):
        return self.left is None

    def isInCooldown(self):
        return self.cooldownUntil is not None and self.cooldownUntil >= datetime.now()

    def isBlacklisted(self):
        return self.rank < 0

    def getObfuscatedId(self):
        salt = date.today().toordinal()
        value = fnv32a([self.id, salt], [User.global_salt])
        # stringify 20 bits
        return ''.join(ID_ALPHA[n % 32] for n in (value, value >> 5, value >> 10, value >> 15))

    def getFormattedName(self):
        if self.username is not None:
            return "@" + self.username
        return self.realname

    def getMessagePriority(self):
        inactive_min = (datetime.now() - self.lastActive) / \
            timedelta(minutes=1)
        c1 = max(RANKS.values()) - max(self.rank, 0)
        c2 = int(inactive_min) & 0xffff
        # lower value means higher priority
        # in this case: prioritize by higher rank, then by lower inactivity time
        return c1 << 16 | c2

    def setLeft(self, v=True):
        self.left = datetime.now() if v else None

    def setBlacklisted(self, reason):
        self.setLeft()
        self.rank = RANKS.banned
        self.blacklistReason = reason

    def addWarning(self, fixed_duration: Optional[timedelta] = None):
        if fixed_duration is not None:
            # Use the provided fixed cooldown duration
            cooldownTime = fixed_duration
        elif self.warnings < len(COOLDOWN_TIME_BEGIN):
            cooldownTime = timedelta(
                minutes=COOLDOWN_TIME_BEGIN[self.warnings])
        else:
            x = self.warnings - len(COOLDOWN_TIME_BEGIN)
            cooldownTime = timedelta(
                minutes=COOLDOWN_TIME_LINEAR_M * x + COOLDOWN_TIME_LINEAR_B)
        self.cooldownUntil = datetime.now() + cooldownTime
        self.warnings += 1
        self.warnExpiry = datetime.now() + timedelta(hours=WARN_EXPIRE_HOURS)
        return cooldownTime

    def removeWarning(self):
        self.warnings = max(self.warnings - 1, 0)
        if self.warnings > 0:
            self.warnExpiry = datetime.now() + timedelta(hours=WARN_EXPIRE_HOURS)
        else:
            self.warnExpiry = None

# abstract db


class ModificationContext():
    def __init__(self, obj, func, lock=None):
        self.obj = obj
        self.func = func
        self.lock = lock
        if self.lock is not None:
            self.lock.acquire()

    def __enter__(self):
        return self.obj

    def __exit__(self, exc_type, *_):
        try:
            if exc_type is None:
                self.func(self.obj)
        finally:
            if self.lock is not None:
                self.lock.release()


class Database():
    def __init__(self):
        self.lock = RLock()
        assert self.__class__ != Database  # do not instantiate directly

    def register_tasks(self, sched):
        raise NotImplementedError()

    def close(self):
        raise NotImplementedError()

    def getUser(self, *, id: Optional[int] = None) -> User:
        raise NotImplementedError()

    def setUser(self, id: int, user: User):
        raise NotImplementedError()

    def addUser(self, user: User):
        raise NotImplementedError()

    def iterateUserIds(self) -> Generator[int, None, None]:
        raise NotImplementedError()

    def getSystemConfig(self) -> Optional[SystemConfig]:
        raise NotImplementedError()

    def setSystemConfig(self, config: SystemConfig):
        raise NotImplementedError()

    def iterateUsers(self) -> Generator[User, None, None]:
        # fallback impl
        with self.lock:
            l = list(self.getUser(id=id) for id in self.iterateUserIds())
        yield from l

    def modifyUser(self, *, id: Optional[int] = None):
        with self.lock:
            user = self.getUser(id=id)
            def callback(newuser): return self.setUser(user.id, newuser)
            return ModificationContext(user, callback, self.lock)

    def modifySystemConfig(self):
        with self.lock:
            config = self.getSystemConfig()
            def callback(newconfig): return self.setSystemConfig(newconfig)
            return ModificationContext(config, callback, self.lock)

# JSON implementation


class JSONDatabase(Database):
    def __init__(self, path):
        super().__init__()
        self.path = path
        self.db = {"systemConfig": None, "users": []}
        try:
            self._load()
        except FileNotFoundError as e:
            pass
        logging.warning("The JSON backend is meant for development only!")

    def register_tasks(self, sched):
        return

    def close(self):
        return

    @staticmethod
    def _systemConfigToDict(config):
        return {"motd": config.motd, "privacy": config.privacy}

    @staticmethod
    def _systemConfigFromDict(d):
        if d is None:
            return None
        config = SystemConfig()
        config.motd = d["motd"]
        config.privacy = d.get("privacy")
        return config

    @staticmethod
    def _userToDict(user):
        d = {}
        for prop in USER_PROPS:
            value = getattr(user, prop)
            if isinstance(value, datetime):
                value = int(value.replace(tzinfo=timezone.utc).timestamp())
            d[prop] = value
        return d

    @staticmethod
    def _userFromDict(d):
        if d is None:
            return None
        props = ["id", "username", "realname", "rank", "blacklistReason",
                 "warnings", "karma", "hideKarma", "debugEnabled"]
        # sendconfirm, votebutton, and credit fields are optional in older DB dumps
        props_d = {
            "tripcode": None,
            "sendconfirm": True,
            "votebutton": True,
            "signenabled": False,
            "tsignenabled": False,
            "credits": 100.0,
            "creditsMessageCount": 0,
            "creditsMediaCount": 0,
            "creditsEarnedToday": 0.0,
        }
        dateprops = ["joined", "left", "lastActive",
                     "cooldownUntil", "warnExpiry", "creditsLastTax", "creditsLastEarnReset"]
        assert set(props).union(props_d.keys()).union(
            dateprops) == set(USER_PROPS)
        user = User()
        for prop in props:
            setattr(user, prop, d[prop])
        for prop, default in props_d.items():
            setattr(user, prop, d.get(prop, default))
        for prop in dateprops:
            value = d.get(prop)
            if value is not None:
                setattr(user, prop, datetime.utcfromtimestamp(value))
            else:
                setattr(user, prop, None)
        return user

    def _load(self):
        with self.lock:
            with open(self.path, "r") as f:
                self.db = json.load(f)

    def _save(self):
        with self.lock:
            with open(self.path + "~", "w") as f:
                json.dump(self.db, f)
            os.replace(self.path + "~", self.path)

    def getUser(self, *, id=None):
        if id is None:
            raise ValueError()
        with self.lock:
            gen = (u for u in self.db["users"] if u["id"] == id)
            try:
                return JSONDatabase._userFromDict(next(gen))
            except StopIteration as e:
                raise KeyError()

    def setUser(self, id, newuser):
        newuser = JSONDatabase._userToDict(newuser)
        with self.lock:
            for i, user in enumerate(self.db["users"]):
                if user["id"] == id:
                    self.db["users"][i] = newuser
                    self._save()
                    return

    def addUser(self, newuser):
        newuser = JSONDatabase._userToDict(newuser)
        with self.lock:
            self.db["users"].append(newuser)
            self._save()

    def iterateUserIds(self):
        with self.lock:
            l = list(u["id"] for u in self.db["users"])
        yield from l

    def getSystemConfig(self):
        with self.lock:
            return JSONDatabase._systemConfigFromDict(self.db["systemConfig"])

    def setSystemConfig(self, config):
        with self.lock:
            self.db["systemConfig"] = JSONDatabase._systemConfigToDict(config)
            self._save()

# SQLite implementation


class SQLiteDatabase(Database):
    def __init__(self, path):
        super().__init__()
        self.db = sqlite3.connect(path, check_same_thread=False,
                                  detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
        self.db.row_factory = sqlite3.Row
        self._ensure_schema()

    def register_tasks(self, sched):
        def f():
            with self.lock:
                self.db.commit()
        sched.register(f, seconds=5)

    def close(self):
        with self.lock:
            self.db.commit()
            self.db.close()

    @staticmethod
    def _systemConfigToDict(config):
        return {"motd": config.motd, "privacy": config.privacy}

    @staticmethod
    def _systemConfigFromDict(d):
        if len(d) == 0:
            return None
        config = SystemConfig()
        config.motd = d["motd"]
        config.privacy = d.get("privacy")
        return config

    @staticmethod
    def _userToDict(user):
        return {prop: getattr(user, prop) for prop in USER_PROPS}

    @staticmethod
    def _userFromRow(r):
        user = User()
        for prop in r.keys():
            setattr(user, prop, r[prop])
        return user

    def _ensure_schema(self):
        def row_exists(table, name):
            cur = self.db.execute("PRAGMA table_info(`" + table + "`);")
            return any(row[1] == name for row in cur)

        with self.lock:
            # create initial schema
            self.db.execute("""
CREATE TABLE IF NOT EXISTS `system_config` (
	`name` TEXT NOT NULL,
	`value` TEXT NOT NULL,
	PRIMARY KEY (`name`)
);
			""".strip())
            self.db.execute("""
CREATE TABLE IF NOT EXISTS `users` (
	`id` BIGINT NOT NULL,
	`username` TEXT,
	`realname` TEXT NOT NULL,
	`rank` INTEGER NOT NULL,
	`joined` TIMESTAMP NOT NULL,
	`left` TIMESTAMP,
	`lastActive` TIMESTAMP NOT NULL,
	`cooldownUntil` TIMESTAMP,
	`blacklistReason` TEXT,
	`warnings` INTEGER NOT NULL,
	`warnExpiry` TIMESTAMP,
	`karma` INTEGER NOT NULL,
	`hideKarma` TINYINT NOT NULL,
	`debugEnabled` TINYINT NOT NULL,
	`tripcode` TEXT,
	`sendconfirm` TINYINT NOT NULL DEFAULT 1,
	`votebutton` TINYINT NOT NULL DEFAULT 1,
	`signenabled` TINYINT NOT NULL DEFAULT 0,
	`tsignenabled` TINYINT NOT NULL DEFAULT 0,
	PRIMARY KEY (`id`)
);
			""".strip())
            # migration
            if not row_exists("users", "tripcode"):
                self.db.execute("ALTER TABLE `users` ADD `tripcode` TEXT")

            # migration for sendconfirm flag (defaults to enabled = 1)
            if not row_exists("users", "sendconfirm"):
                self.db.execute(
                    "ALTER TABLE `users` ADD `sendconfirm` TINYINT NOT NULL DEFAULT 1")

            # migration for votebutton flag (defaults to enabled = 1)
            if not row_exists("users", "votebutton"):
                self.db.execute(
                    "ALTER TABLE `users` ADD `votebutton` TINYINT NOT NULL DEFAULT 1")

            # migration for signenabled flag (defaults to disabled = 0)
            if not row_exists("users", "signenabled"):
                self.db.execute(
                    "ALTER TABLE `users` ADD `signenabled` TINYINT NOT NULL DEFAULT 0")

            # migration for tsignenabled flag (defaults to disabled = 0)
            if not row_exists("users", "tsignenabled"):
                self.db.execute(
                    "ALTER TABLE `users` ADD `tsignenabled` TINYINT NOT NULL DEFAULT 0")

            # migration for credit system
            if not row_exists("users", "credits"):
                self.db.execute(
                    "ALTER TABLE `users` ADD `credits` REAL NOT NULL DEFAULT 100.0")
            if not row_exists("users", "creditsMessageCount"):
                self.db.execute(
                    "ALTER TABLE `users` ADD `creditsMessageCount` INTEGER NOT NULL DEFAULT 0")
            if not row_exists("users", "creditsMediaCount"):
                self.db.execute(
                    "ALTER TABLE `users` ADD `creditsMediaCount` INTEGER NOT NULL DEFAULT 0")
            if not row_exists("users", "creditsLastTax"):
                self.db.execute(
                    "ALTER TABLE `users` ADD `creditsLastTax` TIMESTAMP")
            if not row_exists("users", "creditsEarnedToday"):
                self.db.execute(
                    "ALTER TABLE `users` ADD `creditsEarnedToday` REAL NOT NULL DEFAULT 0.0")
            if not row_exists("users", "creditsLastEarnReset"):
                self.db.execute(
                    "ALTER TABLE `users` ADD `creditsLastEarnReset` TIMESTAMP")

    def getUser(self, *, id=None):
        if id is None:
            raise ValueError()
        sql = "SELECT * FROM users WHERE id = ?"
        param = id
        with self.lock:
            cur = self.db.execute(sql, (param, ))
            row = cur.fetchone()
        if row is None:
            raise KeyError()
        return SQLiteDatabase._userFromRow(row)

    def setUser(self, id, newuser):
        newuser = SQLiteDatabase._userToDict(newuser)
        del newuser['id']  # this is our primary key
        sql = "UPDATE users SET "
        sql += ", ".join("`%s` = ?" % k for k in newuser.keys())
        sql += " WHERE id = ?"
        param = list(newuser.values()) + [id, ]
        with self.lock:
            self.db.execute(sql, param)

    def addUser(self, newuser):
        newuser = SQLiteDatabase._userToDict(newuser)
        sql = "INSERT INTO users("
        sql += ", ".join("`%s`" % k for k in newuser.keys())
        sql += ") VALUES ("
        sql += ", ".join("?" for i in range(len(newuser)))
        sql += ")"
        param = list(newuser.values())
        with self.lock:
            self.db.execute(sql, param)

    def iterateUserIds(self):
        sql = "SELECT `id` FROM users"
        with self.lock:
            cur = self.db.execute(sql)
            l = cur.fetchall()
        yield from l

    def iterateUsers(self):
        sql = "SELECT * FROM users"
        with self.lock:
            cur = self.db.execute(sql)
            l = list(SQLiteDatabase._userFromRow(row) for row in cur)
        yield from l

    def getSystemConfig(self):
        sql = "SELECT * FROM system_config"
        with self.lock:
            cur = self.db.execute(sql)
            d = {row['name']: row['value'] for row in cur}
        return SQLiteDatabase._systemConfigFromDict(d)

    def setSystemConfig(self, config):
        d = SQLiteDatabase._systemConfigToDict(config)
        sql = "REPLACE INTO system_config(`name`, `value`) VALUES (?, ?)"
        with self.lock:
            for k, v in d.items():
                if v is not None:
                    self.db.execute(sql, (k, v))
