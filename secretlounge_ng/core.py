import logging
from datetime import datetime, timedelta
from threading import Lock
from importlib import import_module
from typing import Optional, Dict

from . import replies as rp
from .globals import *
from .database import User, SystemConfig
from .cache import CachedMessage
from .util import genTripcode

# module variables

db = None
ch = None
spam_scores = None
sign_last_used: Dict[int, datetime] = {}
remove_last_used: Dict[int, datetime] = {}
remove_vote_count: Dict[int, int] = {}
# List of timestamps for global removal tracking
global_remove_timestamps: list = []

# Custom message filter function - implement this to block messages
# Should return True to allow the message, False to block it
# Parameters: user (User object), message content/type info
message_filter_func = None

# settings

blacklist_contact: str = None
enable_signing: bool = None
allow_remove_command: bool = None
user_remove_threshold: int = None
user_remove_cooldown_hours: int = None
user_remove_interval: timedelta = None
user_remove_limit_count: int = None
user_remove_global_limit: int = None
user_remove_global_window: timedelta = None
user_remove_consecutive: bool = None
user_remove_consecutive_count: int = None
media_limit_period: Optional[timedelta] = None
sign_interval: timedelta = None

# Credit system settings
credits_enabled: bool = False
credits_starting: float = 100.0
credits_messages_per_credit: int = 20
credits_media_per_credit: int = 5
credits_votes_per_credit: int = 5
credits_vote_cost: float = 1.0
credits_deletion_tax_percent: float = 80.0
credits_daily_tax_percent: float = 0.5
# Credits threshold where tax ramp begins
credits_daily_tax_ramp_start: float = 100.0
# Credits threshold where tax ramp ends (max tax)
credits_daily_tax_ramp_end: float = 200.0
credits_daily_tax_ramp_max: float = 2.0  # Maximum tax percentage at ramp end
credits_negative_timeout_hours: int = 24
credits_daily_earn_max: float = 20.0  # Maximum credits a user can earn per day


class IUserContainer():
    id: int
    username: str
    realname: str

    def __init__(self):
        raise NotImplementedError()


def init(config: dict, _db, _ch):
    global db, ch, spam_scores, blacklist_contact, enable_signing, allow_remove_command, user_remove_threshold, user_remove_cooldown_hours, user_remove_interval, user_remove_limit_count, user_remove_global_limit, user_remove_global_window, user_remove_consecutive, user_remove_consecutive_count, media_limit_period, sign_interval
    global credits_enabled, credits_starting, credits_messages_per_credit, credits_media_per_credit, credits_votes_per_credit, credits_vote_cost, credits_deletion_tax_percent, credits_daily_tax_percent, credits_daily_tax_ramp_start, credits_daily_tax_ramp_end, credits_daily_tax_ramp_max, credits_negative_timeout_hours, credits_daily_earn_max
    db = _db
    ch = _ch
    spam_scores = ScoreKeeper()

    blacklist_contact = config.get("blacklist_contact", "")
    enable_signing = config["enable_signing"]
    allow_remove_command = config["allow_remove_command"]
    user_remove_threshold = config.get("user_remove_threshold", 0)
    user_remove_cooldown_hours = config.get("user_remove_cooldown_hours", 24)
    user_remove_interval = timedelta(seconds=int(
        config.get("user_remove_interval", 600)))
    user_remove_limit_count = config.get("user_remove_limit_count", 3)
    user_remove_global_limit = config.get("user_remove_global_limit", 5)
    user_remove_global_window = timedelta(hours=int(
        config.get("user_remove_global_window", 24)))
    user_remove_consecutive = config.get("user_remove_consecutive", True)
    user_remove_consecutive_count = config.get(
        "user_remove_consecutive_count", 3)
    if "media_limit_period" in config.keys():
        media_limit_period = timedelta(hours=int(config["media_limit_period"]))
    sign_interval = timedelta(seconds=int(
        config.get("sign_limit_interval", 600)))

    # Credit system configuration
    credits_enabled = config.get("credits_enabled", False)
    credits_starting = float(config.get("credits_starting", 20.0))
    credits_messages_per_credit = int(
        config.get("credits_messages_per_credit", 20))
    credits_media_per_credit = int(config.get("credits_media_per_credit", 5))
    credits_votes_per_credit = int(config.get("credits_votes_per_credit", 5))
    credits_vote_cost = float(config.get("credits_vote_cost", 1.0))
    credits_deletion_tax_percent = float(
        config.get("credits_deletion_tax_percent", 80.0))
    credits_daily_tax_percent = float(
        config.get("credits_daily_tax_percent", 0.5))
    credits_daily_tax_ramp_start = float(
        config.get("credits_daily_tax_ramp_start", 50.0))
    credits_daily_tax_ramp_end = float(
        config.get("credits_daily_tax_ramp_end", 150.0))
    credits_daily_tax_ramp_max = float(
        config.get("credits_daily_tax_ramp_max", 2.0))
    credits_negative_timeout_hours = int(
        config.get("credits_negative_timeout_hours", 24))
    credits_daily_earn_max = float(config.get("credits_daily_earn_max", 20.0))

    if config.get("locale"):
        rp.localization = import_module(
            "..replies_" + config["locale"], __name__).localization

    if config.get("secret_salt"):
        User.setSalt(bytes.fromhex(config["secret_salt"]))

    # Load custom message filter if specified
    _load_message_filter(config.get("message_filter", "./message_filter.py"))

    # initialize db if empty
    if db.getSystemConfig() is None:
        c = SystemConfig()
        c.defaults()
        db.setSystemConfig(c)


def _load_message_filter(filter_path: str):
    """
    Load a message filter function from a Python file.

    Args:
            filter_path: Path to a Python file containing a 'message_filter' function
    """
    import os
    import sys
    import importlib.util

    try:
        # Resolve relative path
        if not os.path.isabs(filter_path):
            # Get the directory of the config file (assume it's in the current working directory)
            filter_path = os.path.abspath(filter_path)

        if not os.path.exists(filter_path):
            logging.error("Message filter file not found: %s", filter_path)
            return

        # Load the module from file
        spec = importlib.util.spec_from_file_location(
            "custom_filter", filter_path)
        if spec is None or spec.loader is None:
            logging.error(
                "Failed to load message filter from: %s", filter_path)
            return

        module = importlib.util.module_from_spec(spec)
        sys.modules["custom_filter"] = module
        spec.loader.exec_module(module)

        # Look for the message_filter function
        if hasattr(module, "message_filter"):
            filter_func = getattr(module, "message_filter")
            if callable(filter_func):
                set_message_filter(filter_func)
                logging.info("Loaded message filter from: %s", filter_path)
            else:
                logging.error(
                    "'message_filter' in %s is not callable", filter_path)
        else:
            logging.error(
                "No 'message_filter' function found in: %s", filter_path)

    except Exception as e:
        logging.error("Error loading message filter from %s: %s",
                      filter_path, e)


def set_message_filter(filter_func):
    """
    Set a custom message filter function to control which messages are forwarded.

    Args:
            filter_func: A callable that takes (user: User, is_media: bool, signed: bool, tripcode: bool, message: TMessage)
                                    and returns True to allow the message, False to block it.
                                    Set to None to disable filtering.

    Example:
            def my_filter(user, is_media, signed, tripcode, message):
                    # Block messages from users with low voting
                    if user.voting < -10:
                            return False
                    # Block media from new users
                    if is_media and user.warnings > 0:
                            return False
                    # Block messages containing specific text
                    if message and message.text and "spam" in message.text.lower():
                            return False
                    return True

            core.set_message_filter(my_filter)
    """
    global message_filter_func
    message_filter_func = filter_func


def register_tasks(sched):
    # spam score handling
    sched.register(spam_scores.scheduledTask, seconds=SPAM_INTERVAL_SECONDS)
    # warning removal

    def task():
        now = datetime.now()
        for user in db.iterateUsers():
            if not user.isJoined():
                continue
            if user.warnExpiry is not None and now >= user.warnExpiry:
                with db.modifyUser(id=user.id) as user:
                    user.removeWarning()
    sched.register(task, minutes=15)

    # Credit daily tax task
    def credits_daily_tax_task():
        if not credits_enabled:
            return
        now = datetime.now()
        for user in db.iterateUsers():
            if not user.isJoined():
                continue
            # Check if 24 hours have passed since last tax
            last_tax = getattr(user, 'creditsLastTax', None)
            if last_tax is None:
                last_tax = user.joined
            if now >= last_tax + timedelta(hours=24):
                with db.modifyUser(id=user.id) as user:
                    # Apply daily tax with progressive ramp
                    if user.credits > 0:
                        tax_rate = _calculate_tax_rate(user.credits)
                        tax = user.credits * (tax_rate / 100.0)
                        user.credits = max(0, user.credits - tax)
                    user.creditsLastTax = now
    sched.register(credits_daily_tax_task, hours=1)  # Check every hour


def updateUserFromEvent(user, c_user: IUserContainer):
    user.username = c_user.username
    user.realname = c_user.realname
    user.lastActive = datetime.now()


def getUserByName(username):
    username = username.lstrip("@").lower()
    # there *should* only be a single joined user with a given username
    for user in db.iterateUsers():
        if not user.isJoined():
            continue
        if user.username is not None and user.username.lower() == username:
            return user
    return None


def getUserByOid(oid):
    for user in db.iterateUsers():
        if not user.isJoined():
            continue
        if user.getObfuscatedId() == oid:
            return user
    return None


def requireUser(func):
    def wrapper(c_user, *args, **kwargs):
        if isinstance(c_user, User):
            user = c_user
        else:
            # fetch user from db
            try:
                user = db.getUser(id=c_user.id)
            except KeyError as e:
                return rp.Reply(rp.types.USER_NOT_IN_CHAT)

        # keep db entry up to date
        with db.modifyUser(id=user.id) as user:
            updateUserFromEvent(user, c_user)

        # check for blacklist or absence
        if user.isBlacklisted():
            return rp.Reply(rp.types.ERR_BLACKLISTED, reason=user.blacklistReason, contact=blacklist_contact)
        elif not user.isJoined():
            return rp.Reply(rp.types.USER_NOT_IN_CHAT)

        # call original function
        return func(user, *args, **kwargs)
    return wrapper


def requireRank(need_rank):
    def f(func):
        def wrapper(user, *args, **kwargs):
            assert isinstance(user, User), "you fucked up the decorator order"
            if user.rank < need_rank:
                return
            return func(user, *args, **kwargs)
        return wrapper
    return f

###

# RAM cache for spam scores


class ScoreKeeper():
    def __init__(self):
        self.lock = Lock()
        self.scores = {}

    def increaseSpamScore(self, uid, n):
        """Increase spam score for a user.

        Returns:
            True if message can be sent
            False if rate limited
        """
        with self.lock:
            s = self.scores.get(uid, 0)
            if s > SPAM_LIMIT:
                return False
            elif s + n > SPAM_LIMIT:
                self.scores[uid] = SPAM_LIMIT_HIT
                return s + n <= SPAM_LIMIT_HIT
            self.scores[uid] = s + n
            return True

    def getWaitSeconds(self, uid):
        """Get the number of seconds until user can send messages again."""
        with self.lock:
            s = self.scores.get(uid, 0)
            if s <= SPAM_LIMIT:
                return 0
            # Score decreases by 1 every SPAM_INTERVAL_SECONDS
            # Need to get from current score to SPAM_LIMIT
            decreases_needed = s - SPAM_LIMIT
            return decreases_needed * SPAM_INTERVAL_SECONDS

    def scheduledTask(self):
        with self.lock:
            for uid in list(self.scores.keys()):
                s = self.scores[uid] - 1
                if s <= 0:
                    del self.scores[uid]
                else:
                    self.scores[uid] = s

###

# Event receiver template and Sender class that fwds to all registered event receivers


class Receiver():
    @staticmethod
    def reply(m: rp.Reply, msid: int, who, except_who, reply_to: bool):
        raise NotImplementedError()

    @staticmethod
    def delete(msids: 'list[int]'):
        raise NotImplementedError()

    @staticmethod
    def stop_invoked(who, delete_out: bool):
        raise NotImplementedError()


class Sender(Receiver):  # flawless class hierarchy I know...
    receivers = []

    @staticmethod
    def reply(m, msid, who, except_who, reply_to):
        logging.debug("reply(m.type=%s, msid=%r, reply_to=%r)",
                      rp.types.reverse[m.type], msid, reply_to)
        for r in Sender.receivers:
            r.reply(m, msid, who, except_who, reply_to)

    @staticmethod
    def delete(msids):
        logging.debug("delete(msids=%r)", msids)
        for r in Sender.receivers:
            r.delete(msids)

    @staticmethod
    def stop_invoked(who, delete_out=False):
        logging.debug("stop_invoked(who=%s)", who)
        for r in Sender.receivers:
            r.stop_invoked(who, delete_out)


def registerReceiver(obj):
    assert issubclass(obj, Receiver)
    Sender.receivers.append(obj)
    return obj

####


def user_join(c_user: IUserContainer):
    try:
        user = db.getUser(id=c_user.id)
    except KeyError as e:
        user = None

    if user is not None:
        # check if user can't rejoin
        err = None
        if user.isBlacklisted():
            err = rp.Reply(rp.types.ERR_BLACKLISTED,
                           reason=user.blacklistReason, contact=blacklist_contact)
        elif user.isJoined():
            err = rp.Reply(rp.types.USER_IN_CHAT)
        if err is not None:
            with db.modifyUser(id=user.id) as user:
                updateUserFromEvent(user, c_user)
            return err

        # user rejoins
        absenceTime = datetime.now() - user.left
        with db.modifyUser(id=user.id) as user:
            updateUserFromEvent(user, c_user)
            user.setLeft(False)
        logging.info("%s rejoined chat", user)
        ret = [rp.Reply(rp.types.CHAT_JOIN)]

        motd = db.getSystemConfig().motd
        if motd and absenceTime / timedelta(days=1) >= MOTD_REMIND_DAYS:
            ret.append(rp.Reply(rp.types.CUSTOM, text=motd))

        return ret

    # create new user
    user = User()
    user.defaults()
    user.id = c_user.id
    updateUserFromEvent(user, c_user)
    if not any(db.iterateUserIds()):
        user.rank = RANKS.admin

    # Set starting credits from config
    if credits_enabled:
        user.credits = credits_starting

    logging.info("%s joined chat", user)
    db.addUser(user)
    ret = [rp.Reply(rp.types.CHAT_JOIN)]

    motd = db.getSystemConfig().motd
    if motd:
        ret.append(rp.Reply(rp.types.CUSTOM, text=motd))

    return ret


def force_user_leave(user_id, blocked=True):
    with db.modifyUser(id=user_id) as user:
        user.setLeft()
    if blocked:
        logging.warning("Force leaving %s because bot is blocked", user)
    Sender.stop_invoked(user)


@requireUser
def user_leave(user: User):
    force_user_leave(user.id, blocked=False)
    logging.info("%s left chat", user)

    return rp.Reply(rp.types.CHAT_LEAVE)


def get_help():
    """Get the help message, dynamically including credit info if enabled."""
    return rp.Reply(rp.types.HELP,
                    credits_enabled=credits_enabled,
                    credits_starting=credits_starting,
                    credits_messages_per_credit=credits_messages_per_credit,
                    credits_media_per_credit=credits_media_per_credit,
                    credits_votes_per_credit=credits_votes_per_credit,
                    credits_vote_cost=credits_vote_cost,
                    credits_deletion_tax_percent=credits_deletion_tax_percent,
                    credits_daily_tax_percent=credits_daily_tax_percent,
                    credits_daily_tax_ramp_start=credits_daily_tax_ramp_start,
                    credits_daily_tax_ramp_end=credits_daily_tax_ramp_end,
                    credits_daily_tax_ramp_max=credits_daily_tax_ramp_max,
                    credits_daily_earn_max=credits_daily_earn_max,
                    credits_negative_timeout_hours=credits_negative_timeout_hours)


@requireUser
def get_info(user: User):
    params = {
        "id": user.getObfuscatedId(),
        "username": user.getFormattedName(),
        "rank_i": user.rank,
        "rank": RANKS.reverse[user.rank],
        "voting": user.voting,
        "warnings": user.warnings,
        "warnExpiry": user.warnExpiry,
        "cooldown": user.cooldownUntil if user.isInCooldown() else None,
        "credits": getattr(user, 'credits', credits_starting) if credits_enabled else None,
        "credits_enabled": credits_enabled,
    }
    return rp.Reply(rp.types.USER_INFO, **params)


@requireUser
@requireRank(RANKS.mod)
def get_info_mod(user: User, msid):
    cm = ch.getMessage(msid)
    if cm is None or cm.user_id is None:
        return rp.Reply(rp.types.ERR_NOT_IN_CACHE)

    user2 = db.getUser(id=cm.user_id)
    params = {
        "id": user2.getObfuscatedId(),
        "voting": user2.voting,
        "cooldown": user2.cooldownUntil if user2.isInCooldown() else None,
        "credits": getattr(user2, 'credits', credits_starting) if credits_enabled else None,
        "credits_enabled": credits_enabled,
    }
    return rp.Reply(rp.types.USER_INFO_MOD, **params)


@requireUser
def get_users(user: User):
    if user.rank < RANKS.mod:
        n = sum(1 for user2 in db.iterateUsers() if user2.isJoined())
        return rp.Reply(rp.types.USERS_INFO, count=n)
    active, inactive, black = 0, 0, 0
    for user2 in db.iterateUsers():
        if user2.isBlacklisted():
            black += 1
        elif not user2.isJoined():
            inactive += 1
        else:
            active += 1
    return rp.Reply(rp.types.USERS_INFO_EXTENDED,
                    active=active, inactive=inactive, blacklisted=black,
                    total=active + inactive + black)


@requireUser
@requireRank(RANKS.mod)
def get_moderated_users(user: User):
    """Get a list of users in cooldown or blacklisted."""
    cooldown_users = []
    blacklisted_users = []

    for user2 in db.iterateUsers():
        if user2.isBlacklisted():
            blacklisted_users.append(user2)
        elif user2.isInCooldown():
            cooldown_users.append(user2)

    # Build the response text
    lines = ["<b>Moderated</b>\n"]

    # Cooldown section
    lines.append("<b>In Cooldown:</b>")
    if cooldown_users:
        for u in cooldown_users:
            oid = u.getObfuscatedId()
            username = u.username or "(no username)"
            until = format_datetime(
                u.cooldownUntil) if u.cooldownUntil else "unknown"
            warnings = u.warnings
            lines.append(
                f"  • <code>{oid}</code> @{username} - until {until} (warnings: {warnings})")
    else:
        lines.append("  <i>No users in cooldown</i>")

    lines.append("")  # blank line

    # Blacklisted section
    lines.append("<b>Blacklisted:</b>")
    if blacklisted_users:
        for u in blacklisted_users:
            oid = u.getObfuscatedId()
            username = u.username or "(no username)"
            reason = u.blacklistReason or "(no reason)"
            left_date = format_datetime(u.left) if u.left else "unknown"
            lines.append(
                f"  • <code>{oid}</code> @{username} - since {left_date}")
            lines.append(f"    Reason: {reason}")
    else:
        lines.append("  <i>No blacklisted users</i>")

    lines.append("")
    lines.append(
        f"<b>Total:</b> {len(cooldown_users)} in cooldown, {len(blacklisted_users)} blacklisted")

    return rp.Reply(rp.types.MODERATED_LIST, text="\n".join(lines))


@requireUser
def get_system_text(user: User, key: str):
    if key not in ("motd", "privacy"):
        raise ValueError()
    v = getattr(db.getSystemConfig(), key)
    if v:
        return rp.Reply(rp.types.CUSTOM, text=v)


@requireUser
@requireRank(RANKS.admin)
def set_system_text(user: User, key: str, arg: str):
    if key not in ("motd", "privacy"):
        raise ValueError()
    with db.modifySystemConfig() as config:
        setattr(config, key, arg)
    logging.info("%s set %s to: %r", user, key, arg)
    return rp.Reply(rp.types.SUCCESS)


@requireUser
def toggle_debug(user: User):
    with db.modifyUser(id=user.id) as user:
        user.debugEnabled = not user.debugEnabled
        new = user.debugEnabled
    return rp.Reply(rp.types.BOOLEAN_CONFIG, description="Debug mode", enabled=new)


@requireUser
def toggle_voting(user: User):
    with db.modifyUser(id=user.id) as user:
        user.hideVoting = not user.hideVoting
        new = user.hideVoting
    return rp.Reply(rp.types.BOOLEAN_CONFIG, description="Voting notifications", enabled=not new)


@requireUser
def toggle_sendconfirm(user: User):
    """Toggle whether the user gets a confirmation prompt for QUESTION-filtered messages.

    True = show confirmation button (default behaviour).
    False = bypass and send immediately.
    """
    with db.modifyUser(id=user.id) as user:
        # ensure attribute exists; default True if missing
        cur = getattr(user, 'sendconfirm', True)
        user.sendconfirm = not cur
        new = user.sendconfirm
    return rp.Reply(rp.types.BOOLEAN_CONFIG, description="Ask to confirm sendig messages:", enabled=new)


@requireUser
def toggle_votebutton(user: User):
    """Toggle whether the recipient sees the vote/delete button for messages they receive.

    True = show vote button (default behaviour).
    False = hide vote button on received messages.
    """
    with db.modifyUser(id=user.id) as user:
        cur = getattr(user, 'votebutton', True)
        user.votebutton = not cur
        new = user.votebutton
    return rp.Reply(rp.types.BOOLEAN_CONFIG, description="Show vote button on received messages", enabled=new)


@requireUser
def toggle_signing(user: User):
    """Toggle persistent signing for the user.

    True = all messages are automatically signed (as if using /s).
    False = messages are not automatically signed (default).
    """
    with db.modifyUser(id=user.id) as user:
        cur = getattr(user, 'signenabled', False)
        user.signenabled = not cur
        new = user.signenabled
    return rp.Reply(rp.types.BOOLEAN_CONFIG, description="Auto-sign messages (/s)", enabled=new)


@requireUser
def toggle_tsigning(user: User):
    """Toggle persistent tripcode signing for the user.

    True = all messages are automatically tripcoded (as if using /t).
    False = messages are not automatically tripcoded (default).
    """
    with db.modifyUser(id=user.id) as user:
        cur = getattr(user, 'tsignenabled', False)
        user.tsignenabled = not cur
        new = user.tsignenabled
    return rp.Reply(rp.types.BOOLEAN_CONFIG, description="Auto-tripcode messages (/t)", enabled=new)


@requireUser
def toggle_potentially_unwanted(user: User):
    """Toggle whether the user receives messages flagged as potentially unwanted.

    True = receive potentially unwanted messages.
    False = don't receive potentially unwanted messages (default).
    """
    with db.modifyUser(id=user.id) as user:
        cur = getattr(user, 'showPotentiallyUnwanted', False)
        user.showPotentiallyUnwanted = not cur
        new = user.showPotentiallyUnwanted
    return rp.Reply(rp.types.BOOLEAN_CONFIG, description="Receive potentially unwanted messages", enabled=new)


@requireUser
def get_tripcode(user: User):
    if not enable_signing:
        return rp.Reply(rp.types.ERR_COMMAND_DISABLED)

    return rp.Reply(rp.types.TRIPCODE_INFO, tripcode=user.tripcode)


@requireUser
def set_tripcode(user: User, text: str):
    if not enable_signing:
        return rp.Reply(rp.types.ERR_COMMAND_DISABLED)

    if not 0 < text.find("#") < len(text) - 1:
        return rp.Reply(rp.types.ERR_INVALID_TRIP_FORMAT)
    if "\n" in text or len(text) > 30:
        return rp.Reply(rp.types.ERR_INVALID_TRIP_FORMAT)

    with db.modifyUser(id=user.id) as user:
        user.tripcode = text
    tripname, tripcode = genTripcode(user.tripcode)
    return rp.Reply(rp.types.TRIPCODE_SET, tripname=tripname, tripcode=tripcode)


# Credit system functions

@requireUser
def get_credit_stats(user: User):
    """Get credit system statistics for monitoring inflation."""
    if not credits_enabled:
        return rp.Reply(rp.types.ERR_CREDITS_DISABLED)

    # Gather statistics from all users
    total_credits = 0.0
    active_users = 0
    credits_list = []
    negative_count = 0
    low_count = 0  # 0-50
    medium_count = 0  # 50-100
    high_count = 0  # 100-200
    very_high_count = 0  # 200+

    # Track top earners
    top_global = []  # (credits, user_id, username)
    top_daily = []   # (earned_today, user_id, username)
    now = datetime.now()

    for u in db.iterateUsers():
        if not u.isJoined():
            continue
        active_users += 1
        user_credits = getattr(u, 'credits', credits_starting)
        total_credits += user_credits
        credits_list.append(user_credits)

        if user_credits < 0:
            negative_count += 1
        elif user_credits < 10:
            low_count += 1
        elif user_credits < 50:
            medium_count += 1
        elif user_credits < 150:
            high_count += 1
        else:
            very_high_count += 1

        # Track for leaderboards - show tripcode (hashed) if set, otherwise obfuscated ID
        if u.tripcode:
            tripname, tripcode = genTripcode(u.tripcode)
            display_name = f"{tripname} {tripcode}"
        else:
            display_name = u.getObfuscatedId()
        top_global.append((user_credits, u.id, display_name))

        # Daily earnings (only if within 24h)
        last_reset = getattr(u, 'creditsLastEarnReset', None)
        earned_today = getattr(u, 'creditsEarnedToday', 0.0)
        if last_reset and (now - last_reset) < timedelta(hours=24) and earned_today > 0:
            top_daily.append((earned_today, u.id, display_name))

    if active_users == 0:
        return rp.Reply(rp.types.CREDITS_STATS, text="<b>Credit Stats:</b> No active users")

    avg_credits = total_credits / active_users
    min_credits = min(credits_list)
    max_credits = max(credits_list)
    median_credits = sorted(credits_list)[len(credits_list) // 2]

    # Calculate expected baseline (all users at starting credits)
    expected_total = active_users * credits_starting
    inflation_rate = ((total_credits - expected_total) /
                      expected_total) * 100 if expected_total > 0 else 0

    # Sort and get top 10
    top_global.sort(key=lambda x: x[0], reverse=True)
    top_daily.sort(key=lambda x: x[0], reverse=True)

    lines = [
        "<b>📊 Credit System Statistics</b>",
        "",
        f"<b>Overview:</b>",
        f"  Active users: {active_users}",
        f"  Total credits: {total_credits:.1f}",
        f"  Expected (baseline): {expected_total:.1f}",
        f"  <b>Inflation rate: {inflation_rate:+.1f}%</b>",
        "",
        f"<b>Distribution:</b>",
        f"  Average: {avg_credits:.1f}",
        f"  Median: {median_credits:.1f}",
        f"  Min: {min_credits:.1f}, Max: {max_credits:.1f}",
        "",
        f"<b>Brackets:</b>",
        f"  Negative (&lt;0): {negative_count} ({negative_count/active_users*100:.1f}%)",
        f"  Low (0-10): {low_count} ({low_count/active_users*100:.1f}%)",
        f"  Medium (10-50): {medium_count} ({medium_count/active_users*100:.1f}%)",
        f"  High (50-150): {high_count} ({high_count/active_users*100:.1f}%)",
        f"  Very High (150+): {very_high_count} ({very_high_count/active_users*100:.1f}%)",
        "",
        f"<b>Current Config:</b>",
        f"  Starting: {credits_starting}",
        f"  Earn: {credits_messages_per_credit} msgs or {credits_media_per_credit} media = 1 credit",
        f"  Votes: {credits_votes_per_credit} votes = ±1 credit, voting costs {credits_vote_cost}",
        f"  Deletion tax: {credits_deletion_tax_percent:.0f}%",
        f"  Daily tax: {credits_daily_tax_percent:.1f}% → {credits_daily_tax_ramp_max:.1f}% (ramp {credits_daily_tax_ramp_start:.0f}-{credits_daily_tax_ramp_end:.0f})",
        f"  Daily earn max: {credits_daily_earn_max if credits_daily_earn_max > 0 else 'unlimited'}",
        "",
    ]

    # Top 10 Global (by total credits)
    lines.append("<b>🏆 Top 10 Global (Total Credits):</b>")
    for i, (creds, uid, display_name) in enumerate(top_global[:10], 1):
        lines.append(f"  {i}. {display_name}: {creds:.1f}")
    if not top_global:
        lines.append("  (no users)")
    lines.append("")

    # Top 10 Daily (by credits earned today)
    lines.append("<b>📈 Top 10 Daily (Earned Today):</b>")
    for i, (earned, uid, display_name) in enumerate(top_daily[:10], 1):
        lines.append(f"  {i}. {display_name}: +{earned:.1f}")
    if not top_daily:
        lines.append("  (no earnings today)")
    lines.append("")

    lines.extend([
        "<b>Tuning Tips:</b>",
        "  • Inflation &gt; 0: ↑ daily tax, ↑ vote cost, ↓ earn rates",
        "  • Inflation &lt; 0: ↓ daily tax, ↓ vote cost, ↑ earn rates",
    ])

    return rp.Reply(rp.types.CREDITS_STATS, text="\n".join(lines))


@requireUser
def send_credits(user: User, msid, amount: float):
    """Send credits to another user by replying to their message."""
    if not credits_enabled:
        return rp.Reply(rp.types.ERR_CREDITS_DISABLED)

    if amount <= 0:
        return rp.Reply(rp.types.ERR_CREDITS_INVALID_AMOUNT)

    cm = ch.getMessage(msid)
    if cm is None or cm.user_id is None:
        return rp.Reply(rp.types.ERR_NOT_IN_CACHE)

    if user.id == cm.user_id:
        return rp.Reply(rp.types.ERR_CREDITS_SELF_SEND)

    current_credits = getattr(user, 'credits', credits_starting)
    if current_credits < amount:
        return rp.Reply(rp.types.ERR_CREDITS_INSUFFICIENT, credits=current_credits)

    # Deduct from sender
    with db.modifyUser(id=user.id) as user:
        user.credits = getattr(user, 'credits', credits_starting) - amount
        _subtract_from_daily_earn(user, amount)
        new_balance = user.credits

    # Add to recipient
    user2 = db.getUser(id=cm.user_id)
    with db.modifyUser(id=cm.user_id) as user2:
        user2.credits = getattr(user2, 'credits', credits_starting) + amount
        recipient_balance = user2.credits

    # Notify recipient
    if not user2.hideVoting:
        _push_system_message(
            rp.Reply(rp.types.CREDITS_RECEIVED, amount=amount,
                     credits=recipient_balance),
            who=user2, reply_to=msid)

    logging.info("%s sent %.1f credits to [%s]",
                 user, amount, user2.getObfuscatedId())
    return rp.Reply(rp.types.CREDITS_SENT, amount=amount, credits=new_balance)


@requireUser
def gamble_credits(user: User, amount: float):
    """Gamble credits with a 50% chance to double the amount."""
    import random

    if not credits_enabled:
        return rp.Reply(rp.types.ERR_CREDITS_DISABLED)

    if amount <= 0:
        return rp.Reply(rp.types.ERR_CREDITS_INVALID_AMOUNT)

    current_credits = getattr(user, 'credits', credits_starting)
    if current_credits < amount:
        return rp.Reply(rp.types.ERR_CREDITS_INSUFFICIENT, credits=current_credits)

    # 50% chance to win
    won = random.random() < 0.5

    with db.modifyUser(id=user.id) as user:
        if won:
            # Win: gain the amount (net double)
            user.credits = getattr(user, 'credits', credits_starting) + amount
            new_balance = user.credits
            logging.info("%s gambled %.1f credits and WON (balance: %.1f)",
                         user, amount, new_balance)
            return rp.Reply(rp.types.CREDITS_GAMBLE_WON, winnings=amount, credits=new_balance)
        else:
            # Lose: lose the amount
            user.credits = getattr(user, 'credits', credits_starting) - amount
            _subtract_from_daily_earn(user, amount)
            new_balance = user.credits
            logging.info("%s gambled %.1f credits and LOST (balance: %.1f)",
                         user, amount, new_balance)
            return rp.Reply(rp.types.CREDITS_GAMBLE_LOST, amount=amount, credits=new_balance)


def _calculate_tax_rate(credits: float) -> float:
    """Calculate the daily tax rate based on credit amount with linear ramp.

    Below ramp_start: base tax rate
    Between ramp_start and ramp_end: linearly interpolated
    Above ramp_end: max tax rate
    """
    if credits <= credits_daily_tax_ramp_start:
        return credits_daily_tax_percent
    elif credits >= credits_daily_tax_ramp_end:
        return credits_daily_tax_ramp_max
    else:
        # Linear interpolation between start and end
        ramp_range = credits_daily_tax_ramp_end - credits_daily_tax_ramp_start
        if ramp_range <= 0:
            return credits_daily_tax_percent
        progress = (credits - credits_daily_tax_ramp_start) / ramp_range
        return credits_daily_tax_percent + progress * (credits_daily_tax_ramp_max - credits_daily_tax_percent)


def _check_and_reset_daily_earn(user) -> float:
    """Check if daily earn should be reset and return current earned today value."""
    now = datetime.now()
    last_reset = getattr(user, 'creditsLastEarnReset', None)

    # Reset if never set or if 24 hours have passed
    if last_reset is None or (now - last_reset) >= timedelta(hours=24):
        user.creditsEarnedToday = 0.0
        user.creditsLastEarnReset = now

    return getattr(user, 'creditsEarnedToday', 0.0)


def _try_add_credits(user, amount: float) -> float:
    """Try to add credits respecting daily earn max. Returns amount actually added."""
    if credits_daily_earn_max <= 0:
        # No limit
        user.credits = getattr(user, 'credits', credits_starting) + amount
        user.creditsEarnedToday = getattr(
            user, 'creditsEarnedToday', 0.0) + amount
        return amount

    earned_today = _check_and_reset_daily_earn(user)
    remaining = credits_daily_earn_max - earned_today

    if remaining <= 0:
        return 0.0  # Already at daily max

    actual_amount = min(amount, remaining)
    user.credits = getattr(user, 'credits', credits_starting) + actual_amount
    user.creditsEarnedToday = earned_today + actual_amount
    return actual_amount


def _subtract_from_daily_earn(user, amount: float):
    """Subtract from daily earned credits when user loses credits.
    
    This allows users to earn more credits after losing some, making
    credits_daily_earn_max a net limit rather than gross limit.
    """
    _check_and_reset_daily_earn(user)
    current_earned = getattr(user, 'creditsEarnedToday', 0.0)
    # Allow going negative so losses can offset future earnings
    user.creditsEarnedToday = current_earned - amount


def add_credits_for_message(user_id: int, is_media: bool):
    """Add credits for sending a message. Called from prepare_user_message."""
    if not credits_enabled:
        return

    with db.modifyUser(id=user_id) as user:
        if is_media:
            user.creditsMediaCount = getattr(user, 'creditsMediaCount', 0) + 1
            if user.creditsMediaCount >= credits_media_per_credit:
                _try_add_credits(user, 1.0)
                user.creditsMediaCount = 0
        else:
            user.creditsMessageCount = getattr(
                user, 'creditsMessageCount', 0) + 1
            if user.creditsMessageCount >= credits_messages_per_credit:
                _try_add_credits(user, 1.0)
                user.creditsMessageCount = 0


def apply_credits_deletion_tax(user_id: int):
    """Apply the deletion tax when a user's message is deleted."""
    if not credits_enabled:
        return

    with db.modifyUser(id=user_id) as user:
        current_credits = getattr(user, 'credits', credits_starting)
        tax = current_credits * (credits_deletion_tax_percent / 100.0)
        user.credits = current_credits - tax
        _subtract_from_daily_earn(user, tax)
        logging.info("Applied deletion tax of %.1f to user %s (new balance: %.1f)",
                     tax, user.getObfuscatedId(), user.credits)


def apply_credits_negative_timeout(user_id: int) -> bool:
    """Check if user has negative credits and apply timeout if so. Returns True if timeout was applied."""
    if not credits_enabled:
        return False

    user = db.getUser(id=user_id)
    if getattr(user, 'credits', credits_starting) < 0:
        with db.modifyUser(id=user_id) as user:
            user.cooldownUntil = datetime.now() + timedelta(hours=credits_negative_timeout_hours)
        # Notify the user
        _push_system_message(
            rp.Reply(rp.types.CREDITS_NEGATIVE_TIMEOUT,
                     duration=timedelta(hours=credits_negative_timeout_hours),
                     credits=user.credits),
            who=user)
        logging.info("User %s got timeout for negative credits (%.1f)",
                     user.getObfuscatedId(), user.credits)
        return True
    return False


@requireUser
@requireRank(RANKS.admin)
def promote_user(user: User, username2: str, rank: int):
    user2 = getUserByName(username2)
    if user2 is None:
        return rp.Reply(rp.types.ERR_NO_USER)

    if user2.rank >= rank:
        return
    with db.modifyUser(id=user2.id) as user2:
        user2.rank = rank
    if rank >= RANKS.admin:
        _push_system_message(rp.Reply(rp.types.PROMOTED_ADMIN), who=user2)
    elif rank >= RANKS.mod:
        _push_system_message(rp.Reply(rp.types.PROMOTED_MOD), who=user2)
    logging.info("%s was promoted by %s to: %d", user2, user, rank)
    return rp.Reply(rp.types.SUCCESS)


@requireUser
@requireRank(RANKS.mod)
def send_mod_message(user: User, arg: str):
    text = arg + " ~<b>mods</b>"
    m = rp.Reply(rp.types.CUSTOM, text=text)
    _push_system_message(m)
    logging.info("%s sent mod message: %s", user, arg)


@requireUser
@requireRank(RANKS.admin)
def send_admin_message(user: User, arg: str):
    text = arg + " ~<b>admins</b>"
    m = rp.Reply(rp.types.CUSTOM, text=text)
    _push_system_message(m)
    logging.info("%s sent admin message: %s", user, arg)


@requireUser
@requireRank(RANKS.mod)
def warn_user(user: User, msid, delete=False):
    cm = ch.getMessage(msid)
    if cm is None or cm.user_id is None:
        return rp.Reply(rp.types.ERR_NOT_IN_CACHE)

    if not cm.warned:
        with db.modifyUser(id=cm.user_id) as user2:
            d = user2.addWarning()
            user2.voting -= VOTING_WARN_PENALTY
        _push_system_message(
            rp.Reply(rp.types.GIVEN_COOLDOWN, duration=d, deleted=delete),
            who=user2, reply_to=msid)
        cm.warned = True
    else:
        user2 = db.getUser(id=cm.user_id)
        if not delete:  # allow deleting already warned messages
            return rp.Reply(rp.types.ERR_ALREADY_WARNED)
    if delete:
        # Apply credit deletion tax
        apply_credits_deletion_tax(cm.user_id)
        Sender.delete([msid])
    logging.info("%s warned [%s]%s", user, user2.getObfuscatedId(
    ), delete and " (message deleted)" or "")
    return rp.Reply(rp.types.SUCCESS)


@requireUser
@requireRank(RANKS.mod)
def delete_message(user: User, msid):
    if not allow_remove_command:
        return rp.Reply(rp.types.ERR_COMMAND_DISABLED)

    cm = ch.getMessage(msid)
    if cm is None or cm.user_id is None:
        return rp.Reply(rp.types.ERR_NOT_IN_CACHE)

    user2 = db.getUser(id=cm.user_id)
    # Apply credit deletion tax
    apply_credits_deletion_tax(cm.user_id)
    _push_system_message(rp.Reply(rp.types.MESSAGE_DELETED),
                         who=user2, reply_to=msid)
    Sender.delete([msid])
    logging.info(
        "%s deleted a message from user with oid %s", user, user2.getObfuscatedId())
    return rp.Reply(rp.types.SUCCESS)


@requireUser
@requireRank(RANKS.admin)
def cleanup_messages(user: User, target_user_id: int = None, limit: int = None):
    """
    Delete messages from cache.

    Args:
            user: The user invoking the cleanup (for logging)
            target_user_id: If specified, only delete messages from this user.
                                       If None, deletes messages from all blacklisted users.
            limit: Maximum number of messages to delete. If None, delete all matching messages.

    Returns:
            Reply with count of deleted messages
    """
    return _cleanup_messages_internal(user, target_user_id, limit)


def _cleanup_messages_internal(user: User, target_user_id: int = None, limit: int = None):
    """
    Internal helper for cleanup_messages that doesn't require rank check.

    Args:
            user: The user invoking the cleanup (for logging)
            target_user_id: If specified, only delete messages from this user.
                                       If None, deletes messages from all blacklisted users.
            limit: Maximum number of messages to delete. If None, delete all matching messages.

    Returns:
            Reply with count of deleted messages
    """
    msids = []

    def f(msid: int, cm: CachedMessage):
        if cm.user_id is None:
            return
        if 1337 in cm.upvoted:  # mark that we've been here before
            return

        # If target_user_id is specified, only match that user
        if target_user_id is not None:
            if cm.user_id == target_user_id:
                msids.append(msid)
                cm.upvoted.add(1337)
                # Stop if we've reached the limit
                if limit is not None and len(msids) >= limit:
                    return
        else:
            # Original behavior: cleanup blacklisted users
            user2 = db.getUser(id=cm.user_id)
            if user2.isBlacklisted():
                msids.append(msid)
                cm.upvoted.add(1337)

    ch.iterateMessages(f)

    # Apply limit if specified
    if limit is not None and len(msids) > limit:
        msids = msids[:limit]

    logging.info("%s invoked cleanup (matched: %d)", user, len(msids))
    Sender.delete(msids)
    return rp.Reply(rp.types.DELETION_QUEUED, count=len(msids))


@requireUser
@requireRank(RANKS.admin)
def uncooldown_user(user: User, oid2=None, username2=None):
    if oid2 is not None:
        user2 = getUserByOid(oid2)
        if user2 is None:
            return rp.Reply(rp.types.ERR_NO_USER_BY_ID)
    elif username2 is not None:
        user2 = getUserByName(username2)
        if user2 is None:
            return rp.Reply(rp.types.ERR_NO_USER)
    else:
        raise ValueError()

    if not user2.isInCooldown():
        return rp.Reply(rp.types.ERR_NOT_IN_COOLDOWN)
    with db.modifyUser(id=user2.id) as user2:
        user2.removeWarning()
        was_until = user2.cooldownUntil
        user2.cooldownUntil = None
    # Notify the user their cooldown was removed
    _push_system_message(rp.Reply(rp.types.COOLDOWN_REMOVED), who=user2)
    logging.info("%s removed cooldown from %s (was until %s)",
                 user, user2, format_datetime(was_until))
    return rp.Reply(rp.types.SUCCESS)


@requireUser
@requireRank(RANKS.admin)
def blacklist_user(user: User, msid, reason: str):
    cm = ch.getMessage(msid)
    if cm is None or cm.user_id is None:
        return rp.Reply(rp.types.ERR_NOT_IN_CACHE)

    with db.modifyUser(id=cm.user_id) as user2:
        if user2.rank >= user.rank:
            return
        user2.setBlacklisted(reason)
    cm.warned = True
    # do this before queueing new messages below
    Sender.stop_invoked(user2, True)
    _push_system_message(
        rp.Reply(rp.types.ERR_BLACKLISTED, reason=reason,
                 contact=blacklist_contact),
        who=user2, reply_to=msid)
    Sender.delete([msid])
    logging.info("%s was blacklisted by %s for: %s", user2, user, reason)
    return rp.Reply(rp.types.SUCCESS)


@requireUser
@requireRank(RANKS.admin)
def unblacklist_user(user: User, oid2=None, username2=None):
    # Search all users including blacklisted ones (not just joined users)
    user2 = None
    if oid2 is not None:
        for u in db.iterateUsers():
            if u.getObfuscatedId() == oid2:
                user2 = u
                break
        if user2 is None:
            return rp.Reply(rp.types.ERR_NO_USER_BY_ID)
    elif username2 is not None:
        username2_lower = username2.lstrip("@").lower()
        for u in db.iterateUsers():
            if u.username is not None and u.username.lower() == username2_lower:
                user2 = u
                break
        if user2 is None:
            return rp.Reply(rp.types.ERR_NO_USER)
    else:
        raise ValueError()

    if not user2.isBlacklisted():
        return rp.Reply(rp.types.ERR_NOT_BLACKLISTED)

    with db.modifyUser(id=user2.id) as user2:
        user2.rank = RANKS.user
        user2.blacklistReason = None
        user2.left = None  # Allow them to rejoin

    # Notify the user they were unblacklisted
    _push_system_message(rp.Reply(rp.types.UNBLACKLISTED), who=user2)
    logging.info("%s was unblacklisted by %s", user2, user)
    return rp.Reply(rp.types.SUCCESS)


@requireUser
def give_vote(user: User, msid):
    cm = ch.getMessage(msid)
    if cm is None or cm.user_id is None:
        return rp.Reply(rp.types.ERR_NOT_IN_CACHE)

    if cm.hasUpvoted(user):
        return rp.Reply(rp.types.ERR_ALREADY_UPVOTED)
    elif user.id == cm.user_id:
        return rp.Reply(rp.types.ERR_UPVOTE_OWN_MESSAGE)

    # Credit system: deduct vote cost from voter
    if credits_enabled:
        voter_credits = getattr(user, 'credits', credits_starting)
        if voter_credits < credits_vote_cost:
            return rp.Reply(rp.types.ERR_CREDITS_INSUFFICIENT, credits=voter_credits)
        with db.modifyUser(id=user.id) as user:
            user.credits = getattr(
                user, 'credits', credits_starting) - credits_vote_cost
            _subtract_from_daily_earn(user, credits_vote_cost)

    cm.addUpvote(user)
    user2 = db.getUser(id=cm.user_id)

    # Credit system: count upvotes for recipient (across all messages)
    recipient_credits = None
    recipient_voting = None
    if credits_enabled:
        with db.modifyUser(id=cm.user_id) as user2:
            user2.voting += VOTING_PLUS_ONE
            # Count upvotes - every X upvotes earns 1 credit (respects daily max)
            user2.creditsUpvoteCount = getattr(
                user2, 'creditsUpvoteCount', 0) + 1
            if user2.creditsUpvoteCount >= credits_votes_per_credit:
                _check_and_reset_daily_earn(user2)
                _try_add_credits(user2, 1.0)
                user2.creditsUpvoteCount = 0
            recipient_credits = user2.credits
            recipient_voting = user2.voting
    else:
        with db.modifyUser(id=cm.user_id) as user2:
            user2.voting += VOTING_PLUS_ONE
            recipient_voting = user2.voting
            recipient_credits = getattr(user2, 'credits', credits_starting)

    if not user2.hideVoting:
        _push_system_message(
            rp.Reply(rp.types.VOTING_NOTIFICATION,
                     voting=recipient_voting,
                     credits=recipient_credits),
            who=user2, reply_to=msid)
    return rp.Reply(rp.types.VOTING_THANK_YOU)


@requireUser
def take_vote(user: User, msid):
    cm = ch.getMessage(msid)
    if cm is None or cm.user_id is None:
        return rp.Reply(rp.types.ERR_NOT_IN_CACHE)

    if cm.hasDownvoted(user):
        return rp.Reply(rp.types.ERR_ALREADY_DOWNVOTED)
    elif user.id == cm.user_id:
        return rp.Reply(rp.types.ERR_DOWNVOTE_OWN_MESSAGE)

    # Credit system: deduct vote cost from voter
    if credits_enabled:
        voter_credits = getattr(user, 'credits', credits_starting)
        if voter_credits < credits_vote_cost:
            return rp.Reply(rp.types.ERR_CREDITS_INSUFFICIENT, credits=voter_credits)
        with db.modifyUser(id=user.id) as user:
            user.credits = getattr(
                user, 'credits', credits_starting) - credits_vote_cost
            _subtract_from_daily_earn(user, credits_vote_cost)

    cm.addDownvote(user)
    user2 = db.getUser(id=cm.user_id)

    # Credit system: count downvotes for recipient (lose credits, across all messages)
    recipient_credits = None
    recipient_voting = None
    if credits_enabled:
        with db.modifyUser(id=cm.user_id) as user2:
            user2.voting -= VOTING_PLUS_ONE
            # Count downvotes - every X downvotes loses 1 credit
            user2.creditsDownvoteCount = getattr(
                user2, 'creditsDownvoteCount', 0) + 1
            if user2.creditsDownvoteCount >= credits_votes_per_credit:
                user2.credits = getattr(user2, 'credits', credits_starting) - 1
                _subtract_from_daily_earn(user2, 1.0)
                user2.creditsDownvoteCount = 0
            recipient_credits = user2.credits
            recipient_voting = user2.voting
        # Check if user went negative - apply timeout
        apply_credits_negative_timeout(cm.user_id)
    else:
        with db.modifyUser(id=cm.user_id) as user2:
            user2.voting -= VOTING_PLUS_ONE
            recipient_voting = user2.voting
            recipient_credits = getattr(user2, 'credits', credits_starting)

    if not user2.hideVoting:
        _push_system_message(
            rp.Reply(rp.types.VOTING_NEGATIVE_NOTIFICATION,
                     voting=recipient_voting,
                     credits=recipient_credits),
            who=user2, reply_to=msid)
    return rp.Reply(rp.types.VOTING_TAKEN)


@requireUser
def user_remove_vote(user: User, msid):
    if user_remove_threshold <= 0:
        return rp.Reply(rp.types.ERR_COMMAND_DISABLED)

    cm = ch.getMessage(msid)
    if cm is None or cm.user_id is None:
        return rp.Reply(rp.types.ERR_NOT_IN_CACHE)

    # Don't allow voting to remove system messages
    if cm.user_id is None:
        return

    # Check if user has already voted to remove this message
    if user.id in cm.remove_votes:
        return

    # Check remove command cooldown to prevent abuse (only after limit reached)
    if user_remove_interval.total_seconds() > 0 and user_remove_limit_count > 0:
        last_used = remove_last_used.get(user.id, None)
        vote_count = remove_vote_count.get(user.id, 0)

        # Reset vote count if cooldown period has elapsed
        if last_used and (datetime.now() - last_used) >= user_remove_interval:
            vote_count = 0

        # Check if user has exceeded their vote limit
        if vote_count >= user_remove_limit_count:
            # Check if they're still in cooldown
            if last_used and (datetime.now() - last_used) < user_remove_interval:
                return rp.Reply(rp.types.ERR_SPAMMY_REMOVE)
            # Cooldown elapsed, reset count
            vote_count = 0

    # Add user's vote
    cm.remove_votes.add(user.id)
    votes_needed = user_remove_threshold
    votes_left = votes_needed - len(cm.remove_votes)

    # Update last used timestamp and vote count
    remove_last_used[user.id] = datetime.now()
    vote_count = remove_vote_count.get(user.id, 0)
    remove_vote_count[user.id] = vote_count + 1

    logging.info("%s voted to remove message %d (%d/%d votes)",
                 user, msid, len(cm.remove_votes), votes_needed)

    # Check if threshold has been reached
    if votes_left <= 0:
        # Check global removal limit to prevent raid abuse
        if user_remove_global_limit > 0:
            now = datetime.now()
            # Clean up old timestamps outside the time window
            global global_remove_timestamps
            global_remove_timestamps = [
                ts for ts in global_remove_timestamps
                if (now - ts) < user_remove_global_window
            ]

            # Check if we've reached the global limit
            if len(global_remove_timestamps) >= user_remove_global_limit:
                logging.warning(
                    "Global remove limit reached (%d/%d in last %s), blocking removal",
                    len(global_remove_timestamps), user_remove_global_limit,
                    user_remove_global_window)
                return rp.Reply(rp.types.ERR_GLOBAL_REMOVE_LIMIT)

            # Add current timestamp to the list
            global_remove_timestamps.append(now)

        user2 = db.getUser(id=cm.user_id)

        # Apply credit deletion tax for user-voted removal
        apply_credits_deletion_tax(cm.user_id)

        # Add warning and cooldown if not already warned
        if not cm.warned:
            with db.modifyUser(id=cm.user_id) as user2:
                # Use fixed cooldown duration for user-voted removals
                fixed_duration = timedelta(hours=user_remove_cooldown_hours)
                d = user2.addWarning(fixed_duration=fixed_duration)
                user2.voting -= VOTING_WARN_PENALTY
            _push_system_message(
                rp.Reply(rp.types.GIVEN_COOLDOWN, duration=d, deleted=True),
                who=user2, reply_to=msid)
            cm.warned = True
            logging.info(
                "User [%s] warned due to user-voted removal (cooldown: %s)",
                user2.getObfuscatedId(), d)
        else:
            _push_system_message(
                rp.Reply(rp.types.REMOVE_THRESHOLD_REACHED),
                who=user2, reply_to=msid)

        # Remove messages using cleanup_messages
        if user_remove_consecutive and user_remove_consecutive_count > 0:

            cleanup_result = _cleanup_messages_internal(
                user,
                target_user_id=cm.user_id,
                limit=user_remove_consecutive_count
            )
            logging.info(
                "Removed %d message(s) from %s via user vote",
                cleanup_result.kwargs.get('count', 0), user2)
        else:
            # Only remove the single reported message
            Sender.delete([msid])
            logging.info(
                "Removed message %d by user vote (threshold reached)", msid)

        return rp.Reply(rp.types.SUCCESS)
    else:
        return rp.Reply(rp.types.REMOVE_VOTE_REGISTERED, votes_left=votes_left)


@requireUser
def prepare_user_message(user: User, msg_score: int, *, is_media=False, signed=False, tripcode=False, message=None):
    # prerequisites
    if user.isInCooldown():
        return rp.Reply(rp.types.ERR_COOLDOWN, until=user.cooldownUntil)
    if (signed or tripcode) and not enable_signing:
        return rp.Reply(rp.types.ERR_COMMAND_DISABLED)
    if tripcode and user.tripcode is None:
        return rp.Reply(rp.types.ERR_NO_TRIPCODE)
    if is_media and user.rank < RANKS.mod and media_limit_period is not None:
        if (datetime.now() - user.joined) < media_limit_period:
            return rp.Reply(rp.types.ERR_MEDIA_LIMIT)

    # Apply custom message filter if set
    if message_filter_func is not None:
        try:
            filter_result = message_filter_func(
                user, is_media=is_media, signed=signed, tripcode=tripcode, message=message)

            # Handle both old boolean return type and new FilterAction enum
            if hasattr(filter_result, 'value'):  # It's a FilterAction enum
                # Import FilterAction from message_filter module
                import sys
                if 'custom_filter' in sys.modules:
                    FilterAction = sys.modules['custom_filter'].FilterAction

                    if filter_result == FilterAction.BLOCK:
                        logging.info(
                            "Message from user %s blocked by custom filter", user)
                        return rp.Reply(rp.types.ERR_BLOCKED_BY_FILTER)
                    elif filter_result == FilterAction.QUESTION:
                        logging.info(
                            "Message from user %s requires confirmation by custom filter", user)
                        return rp.Reply(rp.types.ERR_QUESTION_FILTER)
                    elif filter_result == FilterAction.POTENTIALLY_UNWANTED:
                        logging.info(
                            "Message from user %s marked as potentially unwanted", user)
                        return rp.Reply(rp.types.POTENTIALLY_UNWANTED_FILTER)
                    # FilterAction.ALLOW falls through
            elif not filter_result:  # Old boolean style: False means block
                logging.info(
                    "Message from user %s blocked by custom filter", user)
                return rp.Reply(rp.types.ERR_BLOCKED_BY_FILTER)
        except Exception as e:
            logging.error("Error in custom message filter: %s", e)
            # Continue processing message if filter errors out

    ok = spam_scores.increaseSpamScore(user.id, msg_score)
    if not ok:
        wait_seconds = spam_scores.getWaitSeconds(user.id)
        return rp.Reply(rp.types.ERR_SPAMMY, wait_seconds=wait_seconds)

    # enforce signing cooldown
    if signed and sign_interval.total_seconds() > 1:
        last_used = sign_last_used.get(user.id, None)
        if last_used and (datetime.now() - last_used) < sign_interval:
            remaining = sign_interval - (datetime.now() - last_used)
            wait_seconds = int(remaining.total_seconds()) + 1
            return rp.Reply(rp.types.ERR_SPAMMY_SIGN, wait_seconds=wait_seconds)
        sign_last_used[user.id] = datetime.now()

    # Credit system: earn credits for sending messages
    add_credits_for_message(user.id, is_media)

    return ch.assignMessageId(CachedMessage(user.id))

# who is None -> to everyone except the user <except_who> (if applicable)
# who is not None -> only to the user <who>
# reply_to: msid the message is in reply to


def _push_system_message(m, *, who=None, except_who=None, reply_to=None):
    msid = None
    if who is None:  # we only need an ID if multiple people can see the msg
        msid = ch.assignMessageId(CachedMessage())
    Sender.reply(m, msid, who, except_who, reply_to)
