import telebot
import logging
import time
import json
import re
from typing import Optional
from functools import partial
from datetime import datetime, timedelta

from . import core
from . import replies as rp
from .util import MutablePriorityQueue, genTripcode
from .cache import CachedMessage
from .globals import *

# module constants
MEDIA_FILTER_TYPES = ("photo", "animation", "document",
                      "video", "video_note", "sticker")
CAPTIONABLE_TYPES = ("photo", "audio", "animation",
                     "document", "video", "voice")
COPYABLE_TYPES = ("story", "location", "venue", "contact", "video_note")
HIDE_FORWARD_FROM = set(s.lower() for s in [
    "anonymize_bot", "anonfacebot", "anonymousforwarderbot", "anonomiserbot",
    "anonymous_forwarder_nashenasbot", "anonymous_forward_bot", "mirroring_bot",
    "anonymizbot", "forwardscoverbot", "anonymousmcjnbot", "mirroringbot",
    "anonymousforwarder_bot", "anonymousforwardbot", "anonymous_forwarder_bot",
    "anonymousforwardsbot", "hiddenlybot", "forwardcoveredbot", "anonym2bot",
    "antiforwardedbot", "noforward_bot", "anonymous_telegram_bot",
    "forwards_cover_bot", "forwardshidebot", "forwardscoversbot",
    "noforwardssourcebot", "antiforwarded_v2_bot", "forwardcoverzbot",
    "captionremove_bot", "caption_remove_bot", "nocaption_bot",
    "captionsremovebot", "captionremover_bot", "forwardcoversrobot",
    "v2forwardscoverbot", "album_collector_bot", "forwards_cover_kr_bot",
])

assert len(set(CAPTIONABLE_TYPES).intersection(COPYABLE_TYPES)) == 0

TMessage = telebot.types.Message

# module variables
bot: telebot.TeleBot = None
db = None
ch = None
message_queue = None
registered_commands = {}

# settings
linked_network: dict = None


def init(config: dict, _db, _ch):
    global bot, db, ch, message_queue, linked_network
    if not config.get("bot_token") or ":" not in config["bot_token"]:
        logging.error("No Telegram bot token specified")
        exit(1)

    logging.getLogger("urllib3").setLevel(
        logging.WARNING)  # very noisy with debug otherwise
    telebot.apihelper.READ_TIMEOUT = 20

    bot = telebot.TeleBot(config["bot_token"], threaded=False)
    db = _db
    ch = _ch
    message_queue = MutablePriorityQueue()

    allow_contacts = config["allow_contacts"]
    allow_documents = config["allow_documents"]
    linked_network = config.get("linked_network")
    if linked_network is not None and not isinstance(linked_network, dict):
        logging.error("Wrong type for 'linked_network'")
        exit(1)
    message_reaction_upvote = config.get("message_reaction_upvote", True)

    types = [
        "text", "location", "venue", "story", "animation", "audio", "photo",
        "sticker", "video", "video_note", "voice", "poll"
    ]
    if allow_contacts:
        types += ["contact"]
    if allow_documents:
        types += ["document"]

    cmds = [
        "start", "stop", "users", "info", "help", "motd", "toggledebug", "togglevoting",
        "modsay", "adminsay", "mod", "admin", "warn", "delete", "remove", "uncooldown", "blacklist", "unblacklist",
        "s", "tripcode", "t", "purgebanned", "sendconfirm", "votebutton", "moderated",
        "toggles", "togglet", "togglepotentiallyunwanted", "credit", "creditstats", "gamblecredits"
    ]
    for c in cmds:  # maps /<c> to the function cmd_<c>
        c = c.lower()
        registered_commands[c] = globals()["cmd_" + c]

    def wrap(func, *args, **kwargs):
        try:
            func(*args, **kwargs)
        except Exception as e:
            logging.exception("Exception raised in event handler %r", func)

    bot.message_handler(
        content_types=types, chat_types=["private"]
    )(partial(wrap, relay))
    if message_reaction_upvote:
        bot.message_reaction_handler()(partial(wrap, message_reaction))

    # Register callback query handler for inline button votes
    bot.callback_query_handler(func=lambda call: True)(
        partial(wrap, handle_callback_query))


def run():
    assert not bot.threaded
    while True:
        try:
            bot.polling(
                non_stop=True, long_polling_timeout=49,
                allowed_updates=["message",
                                 "message_reaction", "callback_query"]
            )
        except Exception as e:
            # you're not supposed to call .polling() more than once but I'm left with no choice
            logging.warning(
                "%s while polling Telegram, retrying.", type(e).__name__)
            time.sleep(1)


def register_tasks(sched):
    # cache expiration
    def task():
        ids = ch.expire()
        if len(ids) == 0:
            return
        n = 0

        def f(item):
            nonlocal n
            if item.msid in ids:
                n += 1
                return True
            return False
        message_queue.delete(f)
        if n > 0:
            logging.warning(
                "Failed to deliver %d messages before they expired from cache.", n)
    sched.register(task, hours=6)  # (1/4) * cache duration

# Wraps a telegram user in a consistent class


class UserContainer(core.IUserContainer):
    def __init__(self, u: telebot.types.User):
        self.id = u.id
        self.username = u.username
        self.realname = u.first_name
        if u.last_name is not None:
            self.realname += " " + u.last_name


def split_command(text: str):
    if " " not in text:
        return text[1:].lower(), ""
    pos = text.find(" ")
    return text[1:pos].lower(), text[pos+1:].strip()


def takesArgument(optional=False):
    def f(func):
        def wrap(ev: TMessage):
            _, arg = split_command(ev.text)
            if arg == "" and not optional:
                return
            return func(ev, arg)
        return wrap
    return f


def wrap_core(func, reply_to=False):
    def f(ev):
        m = func(UserContainer(ev.from_user))
        send_answer(ev, m, reply_to=reply_to)
    return f


def send_answer(ev: TMessage, m, reply_to=False):
    if m is None:
        return
    elif isinstance(m, list):
        for m2 in m:
            send_answer(ev, m2, reply_to)
        return

    reply_to = ev.message_id if reply_to else None

    def f(ev=ev, m=m):
        while True:
            try:
                send_to_single_inner(ev.chat.id, m, reply_to=reply_to)
            except telebot.apihelper.ApiException as e:
                retry = check_telegram_exc(e, None)
                if retry:
                    continue
                return
            break

    try:
        user = db.getUser(id=ev.from_user.id)
    except KeyError as e:
        user = None  # happens on e.g. /start
    put_into_queue(user, None, f)

# TODO: find a better place for this


def allow_message_text(text):
    if text is None or text == "":
        return True
    # Mathematical Alphanumeric Symbols: has convincing looking bold text
    if any(0x1D400 <= ord(c) <= 0x1D7FF for c in text):
        return False
    return True

# determine spam score for message `ev`


def calc_spam_score(ev: TMessage):
    if not allow_message_text(ev.text) or not allow_message_text(ev.caption):
        return 999

    s = SCORE_BASE_MESSAGE
    if is_forward(ev):
        s = SCORE_BASE_FORWARD

    if ev.content_type == "sticker":
        return SCORE_STICKER
    elif ev.content_type == "text":
        pass
    else:
        return s
    s += len(ev.text) * SCORE_TEXT_CHARACTER + \
        ev.text.count("\n") * SCORE_TEXT_LINEBREAK
    return s

###

# Formatting for user messages, which are largely passed through as-is


class FormattedMessage():
    html: bool
    content: str

    def __init__(self, html, content):
        self.html = html
        self.content = content


class FormattedMessageBuilder():
    text_content: str
    # initialize builder with first argument that isn't None

    def __init__(self, *args):
        self.text_content = next(filter(lambda x: x is not None, args))
        self.inserts = {}

    def get_text(self):
        return self.text_content

    # insert `content` at `pos`, `html` indicates HTML or plaintext
    # if `pre` is set content will be inserted *before* existing insertions
    def insert(self, pos, content, html=False, pre=False):
        def cat(a, b):
            return (b + a) if pre else (a + b)
        i = self.inserts.get(pos)
        if i is not None:
            # only turn insert into HTML if strictly necessary
            if i[0] == html:
                i = (i[0], cat(i[1], content))
            elif not i[0]:
                i = (True, cat(escape_html(i[1]), content))
            else:  # not html
                i = (True, cat(i[1], escape_html(content)))
        else:
            i = (html, content)
        self.inserts[pos] = i

    def prepend(self, content: str, html=False):
        self.insert(0, content, html, True)

    def append(self, content: str, html=False):
        self.insert(len(self.text_content), content, html)

    def enclose(self, pos1: int, pos2: int, content_begin: str, content_end: str, html=False):
        self.insert(pos1, content_begin, html)
        self.insert(pos2, content_end, html, True)

    # build message, will consume all inserts
    def build(self, force=False) -> Optional[FormattedMessage]:
        if len(self.inserts) == 0:
            if force:
                return FormattedMessage(False, self.text_content)
            return None
        html = any(i[0] for i in self.inserts.values())
        def norm(i): return i[1] if i[0] == html else escape_html(i[1])
        s = ""
        for idx, c in enumerate(self.text_content):
            i = self.inserts.pop(idx, None)
            if i is not None:
                s += norm(i)
            s += escape_html(c) if html else c
        i = self.inserts.pop(len(self.text_content), None)
        if i is not None:
            s += norm(i)
        assert len(self.inserts) == 0
        return FormattedMessage(html, s)

# Append inline URLs from the message `ev` to `fmt` so they are preserved even
# if the original formatting is stripped


def formatter_replace_links(ev: TMessage, fmt: FormattedMessageBuilder):
    entities = ev.caption_entities or ev.entities
    if entities is None:
        return
    for ent in entities:
        if ent.type == "text_link":
            if ent.url.startswith("tg://"):
                continue  # doubt anyone needs these
            if "://t.me/" in ent.url and "?start=" in ent.url:
                continue  # deep links look ugly and are likely not important
            fmt.append("\n(%s)" % ent.url)

# Add inline links for >>>/name/ syntax depending on configuration


def formatter_network_links(fmt: FormattedMessageBuilder):
    if not linked_network:
        return
    for m in re.finditer(r'>>>/([a-zA-Z0-9]+)/', fmt.get_text()):
        link = linked_network.get(m.group(1).lower())
        if link:
            # we use a tg:// URL here because it avoids web page preview
            fmt.enclose(m.start(), m.end(),
                        "<a href=\"tg://resolve?domain=%s\">" % link, "</a>", True)

# Add signed message formatting for User `user` to `fmt`


def formatter_signed_message(user: core.User, fmt: FormattedMessageBuilder):
    fmt.append(" <a href=\"tg://user?id=%d\">" % user.id, True)
    fmt.append("~~" + user.getFormattedName())
    fmt.append("</a>", True)

# Add tripcode message formatting for User `user` to `fmt`


def formatter_tripcoded_message(user: core.User, fmt: FormattedMessageBuilder):
    tripname, tripcode = genTripcode(user.tripcode)
    # due to how prepend() works the string is built right-to-left
    fmt.prepend("</code>:\n", True)
    fmt.prepend(tripcode)
    fmt.prepend("</b> <code>", True)
    fmt.prepend(tripname)
    fmt.prepend("<b>", True)

###

# Message sending (queue-related)


class QueueItem():
    __slots__ = ("user_id", "msid", "func")

    def __init__(self, user, msid, func):
        self.user_id = None  # who this item is being delivered to
        if user is not None:
            self.user_id = user.id
        self.msid = msid  # message id connected to this item
        self.func = func

    def call(self):
        try:
            self.func()
        except Exception as e:
            logging.exception("Exception raised during queued message")


def get_priority_for(user):
    if user is None:
        # user doesn't exist (yet): handle as rank=0, lastActive=<now>
        # cf. User.getMessagePriority in database.py
        return max(RANKS.values()) << 16
    return user.getMessagePriority()


def put_into_queue(user, msid, f):
    message_queue.put(get_priority_for(user), QueueItem(user, msid, f))


def send_thread():
    while True:
        item = message_queue.get()
        item.call()

###

# Message sending (functions)


def is_forward(ev: TMessage):
    return ev.forward_origin is not None


def should_hide_forward(ev: TMessage):
    # Hide forwards from anonymizing bots that have recently become popular.
    # The main reason is that the bot API heavily penalizes forwarding and the
    # 'Forwarded from Anonymize Bot' provides no additional/useful information.
    if isinstance(ev.forward_origin, telebot.types.MessageOriginUser):
        return (ev.forward_origin.sender_user.username or "").lower() in HIDE_FORWARD_FROM
    return False


def reply_parameters(message_id: int) -> telebot.types.ReplyParameters:
    return telebot.types.ReplyParameters(message_id, allow_sending_without_reply=True)


def resend_message(chat_id, ev: TMessage, reply_to=None, force_caption: Optional[FormattedMessage] = None, reply_markup=None):
    if should_hide_forward(ev):
        pass
    elif is_forward(ev):
        # forward message instead of re-sending the contents
        return bot.forward_message(chat_id, ev.chat.id, ev.message_id)

    kwargs = {}
    if reply_to is not None:
        kwargs["reply_parameters"] = reply_parameters(reply_to)
    if reply_markup is not None:
        kwargs["reply_markup"] = reply_markup
    if ev.content_type in CAPTIONABLE_TYPES:
        if force_caption is not None:
            kwargs["caption"] = force_caption.content
            if force_caption.html:
                kwargs["parse_mode"] = "HTML"
        else:
            kwargs["caption"] = ev.caption
        if ev.show_caption_above_media:
            kwargs["show_caption_above_media"] = True

    # re-send message based on content type
    if ev.content_type == "text":
        return bot.send_message(chat_id, ev.text, **kwargs)
    elif ev.content_type == "photo":
        photo = sorted(ev.photo, key=lambda e: e.width *
                       e.height, reverse=True)[0]
        return bot.send_photo(chat_id, photo.file_id, **kwargs)
    elif ev.content_type == "audio":
        for prop in ("performer", "title"):
            kwargs[prop] = getattr(ev.audio, prop)
        return bot.send_audio(chat_id, ev.audio.file_id, **kwargs)
    elif ev.content_type == "animation":
        return bot.send_animation(chat_id, ev.animation.file_id, **kwargs)
    elif ev.content_type == "document":
        return bot.send_document(chat_id, ev.document.file_id, **kwargs)
    elif ev.content_type == "video":
        return bot.send_video(chat_id, ev.video.file_id, **kwargs)
    elif ev.content_type == "voice":
        return bot.send_voice(chat_id, ev.voice.file_id, **kwargs)
    elif ev.content_type in COPYABLE_TYPES:
        return bot.copy_message(chat_id, ev.chat.id, ev.message_id)
    elif ev.content_type == "sticker":
        return bot.send_sticker(chat_id, ev.sticker.file_id, **kwargs)
    elif ev.content_type == "poll":
        # we generally shouldn't get here, but if we do ignore silently
        return
    else:
        raise NotImplementedError("content_type = %s" % ev.content_type)

# send a message `ev` (multiple types possible) to Telegram ID `chat_id`
# returns the sent Telegram message


def send_to_single_inner(chat_id, ev, reply_to=None, force_caption=None, reply_markup=None):
    if isinstance(ev, rp.Reply):
        kwargs2 = {}
        if reply_to is not None:
            kwargs2["reply_parameters"] = reply_parameters(reply_to)
        if reply_markup is not None:
            kwargs2["reply_markup"] = reply_markup
        if ev.type == rp.types.CUSTOM:
            kwargs2["link_preview_options"] = telebot.types.LinkPreviewOptions(
                is_disabled=True)
        elif ev.type == rp.types.VOTING_NOTIFICATION:
            kwargs2["message_effect_id"] = "5107584321108051014"  # thumbs up
        kwargs2["parse_mode"] = "HTML"
        return bot.send_message(chat_id, rp.formatForTelegram(ev), **kwargs2)
    elif isinstance(ev, FormattedMessage):
        kwargs2 = {}
        if reply_to is not None:
            kwargs2["reply_parameters"] = reply_parameters(reply_to)
        if reply_markup is not None:
            kwargs2["reply_markup"] = reply_markup
        if ev.html:
            kwargs2["parse_mode"] = "HTML"
        return bot.send_message(chat_id, ev.content, **kwargs2)

    return resend_message(chat_id, ev, reply_to=reply_to, force_caption=force_caption, reply_markup=reply_markup)

# queue sending of a single message `ev` (multiple types possible) to User `user`
# this includes saving of the sent message id to the cache mapping.
# `reply_msid` can be a msid of the message that will be replied to
# `force_caption` can be a FormattedMessage to set the caption for resent media


def send_to_single(ev, msid, user, *, reply_msid=None, force_caption=None):
    # set reply_to_message_id if applicable
    reply_to = None
    if reply_msid is not None:
        reply_to = ch.getMapping(user.id, reply_msid)

    # who we're sending to (use immediately where needed)
    user_id = user.id

    # Check if message needs a vote button or potentially unwanted button
    reply_markup = None
    if msid is not None:
        cm = ch.getMessage(msid)
        if cm is not None:
            # Check for potentially unwanted message button
            if cm.is_potentially_unwanted:
                markup = telebot.types.InlineKeyboardMarkup()
                button = telebot.types.InlineKeyboardButton(
                    text="Potentially unwanted. Stop receiving such messages?",
                    callback_data=f"hide_potentially_unwanted:{user_id}"
                )
                markup.add(button)
                reply_markup = markup
            # Check for vote button
            elif cm.needs_vote_button:
                # Check if user is in cooldown - don't show vote button to users in cooldown
                try:
                    recipient_user = db.getUser(id=user_id)
                    # Don't show vote button to users in cooldown or who disabled it
                    if recipient_user.isInCooldown() or not getattr(recipient_user, 'votebutton', True):
                        # User is in cooldown or has disabled vote buttons; don't add vote button
                        pass
                    else:
                        # Create inline keyboard with delete vote button
                        markup = telebot.types.InlineKeyboardMarkup()
                        button = telebot.types.InlineKeyboardButton(
                            text="Is this against the rules? Delete",
                            callback_data=f"vote_delete:{msid}"
                        )
                        markup.add(button)
                        reply_markup = markup
                except KeyError:
                    # User not in database, treat as not in cooldown
                    markup = telebot.types.InlineKeyboardMarkup()
                    button = telebot.types.InlineKeyboardButton(
                        text="Is this against the rules? Delete",
                        callback_data=f"vote_delete:{msid}"
                    )
                    markup.add(button)
                    reply_markup = markup

    def f():
        while True:
            try:
                ev2 = send_to_single_inner(
                    user_id, ev, reply_to, force_caption, reply_markup)
            except telebot.apihelper.ApiException as e:
                retry = check_telegram_exc(e, user_id)
                if retry:
                    continue
                return
            break
        ch.saveMapping(user_id, msid, ev2.message_id)
    put_into_queue(user, msid, f)

# delete message with `id` in Telegram chat `user_id`


def delete_message_inner(user_id, id):
    while True:
        try:
            bot.delete_message(user_id, id)
        except telebot.apihelper.ApiException as e:
            retry = check_telegram_exc(e, None)
            if retry:
                continue
            return
        break

# look at given Exception `e`, force-leave user if bot was blocked
# returns True if message sending should be retried


def check_telegram_exc(e, user_id):
    errmsgs = ["bot was blocked by the user", "user is deactivated",
               "PEER_ID_INVALID", "bot can't initiate conversation",
               "chat not found"]
    if any(msg in e.result.text for msg in errmsgs):
        if user_id is not None:
            core.force_user_leave(user_id)
        return False

    if "Too Many Requests" in e.result.text:
        d = json.loads(e.result.text)["parameters"]["retry_after"]
        # supposedly this is in seconds, but you sometimes get 100 or even 2000
        d = min(d, 30)
        logging.warning("API rate limit hit, waiting for %ds", d)
        time.sleep(d)
        return True  # retry

    if "VOICE_MESSAGES_FORBIDDEN" in e.result.text:
        return False

    logging.exception("API exception")
    return False

####

# Event receiver: handles all things the core decides to do "on its own":
# e.g. voting notifications, deletion of messages, signed messages
# This does *not* include direct replies to commands or relaying of messages.


@core.registerReceiver
class MyReceiver(core.Receiver):
    @staticmethod
    def reply(m, msid, who, except_who, reply_msid):
        if who is not None:
            return send_to_single(m, msid, who, reply_msid=reply_msid)

        for user in db.iterateUsers():
            if not user.isJoined():
                continue
            if user == except_who and not user.debugEnabled:
                continue
            send_to_single(m, msid, user, reply_msid=reply_msid)

    @staticmethod
    def delete(msids):
        msids_set = set(msids)
        # first stop actively delivering this message
        message_queue.delete(lambda item: item.msid in msids_set)
        # then delete all instances that have already been sent
        msids_owner = []
        for msid in msids:
            tmp = ch.getMessage(msid)
            msids_owner.append(None if tmp is None else tmp.user_id)
        assert len(msids_owner) == len(msids)
        # FIXME: there's a hard to avoid race condition here:
        # if a message is currently being sent, but finishes after we grab the
        # message ids it will never be deleted
        for user in db.iterateUsers():
            if not user.isJoined():
                continue

            for j, msid in enumerate(msids):
                if user.id == msids_owner[j] and not user.debugEnabled:
                    continue
                id = ch.getMapping(user.id, msid)
                if id is None:
                    continue
                user_id = user.id

                def f(user_id=user_id, id=id):
                    delete_message_inner(user_id, id)
                # msid=None here since this is a deletion, not a message being sent
                put_into_queue(user, None, f)

                # Also delete associated vote count messages for this user
                vote_count_msgs = ch.getVoteCountMessages(msid)
                if user_id in vote_count_msgs:
                    vote_count_msg_id = vote_count_msgs[user_id]

                    def delete_vote_count(user_id=user_id, msg_id=vote_count_msg_id):
                        delete_message_inner(user_id, msg_id)
                    put_into_queue(user, None, delete_vote_count)

        # drop the mappings for this message so the id doesn't end up used e.g. for replies
        for msid in msids_set:
            ch.deleteMappings(msid)
            # also delete vote count message records
            ch.deleteVoteCountMessages(msid)

    @staticmethod
    def stop_invoked(user, delete_out):
        # delete pending messages to be delivered *to* the user
        message_queue.delete(
            lambda item, user_id=user.id: item.user_id == user_id)
        if not delete_out:
            return
        # delete all pending messages written *by* the user too

        def f(item):
            if item.msid is None:
                return False
            cm = ch.getMessage(item.msid)
            if cm is None:
                return False
            return cm.user_id == user.id
        message_queue.delete(f)

####


cmd_start = wrap_core(core.user_join)
cmd_stop = wrap_core(core.user_leave)


cmd_users = wrap_core(core.get_users)


def cmd_info(ev):
    c_user = UserContainer(ev.from_user)
    if ev.reply_to_message is None:
        return send_answer(ev, core.get_info(c_user), True)

    reply_msid = ch.findMapping(
        ev.from_user.id, ev.reply_to_message.message_id)
    if reply_msid is None:
        return send_answer(ev, rp.Reply(rp.types.ERR_NOT_IN_CACHE), True)
    return send_answer(ev, core.get_info_mod(c_user, reply_msid), True)


def cmd_help(ev):
    send_answer(ev, core.get_help(), True)


@takesArgument(optional=True)
def cmd_motd(ev: TMessage, arg):
    c_user = UserContainer(ev.from_user)

    m = core.set_system_text(c_user, "motd", arg) if arg else None
    if not m:
        m = core.get_system_text(c_user, "motd")
    send_answer(ev, m, reply_to=True)


@takesArgument(optional=True)
def cmd_tripcode(ev, arg):
    c_user = UserContainer(ev.from_user)

    if arg == "":
        send_answer(ev, core.get_tripcode(c_user))
    else:
        send_answer(ev, core.set_tripcode(c_user, arg))


cmd_toggledebug = wrap_core(core.toggle_debug)
cmd_togglevoting = wrap_core(core.toggle_voting)
cmd_sendconfirm = wrap_core(core.toggle_sendconfirm)
cmd_votebutton = wrap_core(core.toggle_votebutton)
cmd_toggles = wrap_core(core.toggle_signing)
cmd_togglet = wrap_core(core.toggle_tsigning)
cmd_togglepotentiallyunwanted = wrap_core(core.toggle_potentially_unwanted)


@takesArgument()
def cmd_modsay(ev, arg):
    c_user = UserContainer(ev.from_user)
    arg = escape_html(arg)
    return send_answer(ev, core.send_mod_message(c_user, arg), True)


@takesArgument()
def cmd_adminsay(ev, arg):
    c_user = UserContainer(ev.from_user)
    arg = escape_html(arg)
    return send_answer(ev, core.send_admin_message(c_user, arg), True)


@takesArgument()
def cmd_mod(ev, arg):
    c_user = UserContainer(ev.from_user)
    arg = arg.lstrip("@")
    send_answer(ev, core.promote_user(c_user, arg, RANKS.mod), True)


@takesArgument()
def cmd_admin(ev, arg):
    c_user = UserContainer(ev.from_user)
    arg = arg.lstrip("@")
    send_answer(ev, core.promote_user(c_user, arg, RANKS.admin), True)


def cmd_warn(ev: TMessage, delete=False, only_delete=False):
    c_user = UserContainer(ev.from_user)

    if ev.reply_to_message is None:
        return send_answer(ev, rp.Reply(rp.types.ERR_NO_REPLY), True)

    reply_msid = ch.findMapping(
        ev.from_user.id, ev.reply_to_message.message_id)
    if reply_msid is None:
        return send_answer(ev, rp.Reply(rp.types.ERR_NOT_IN_CACHE), True)
    if only_delete:
        r = core.delete_message(c_user, reply_msid)
    else:
        r = core.warn_user(c_user, reply_msid, delete)
    send_answer(ev, r, True)


cmd_delete = partial(cmd_warn, delete=True)


def cmd_remove(ev: TMessage):
    c_user = UserContainer(ev.from_user)

    if ev.reply_to_message is None:
        return send_answer(ev, rp.Reply(rp.types.ERR_NO_REPLY), True)

    reply_msid = ch.findMapping(
        ev.from_user.id, ev.reply_to_message.message_id)
    if reply_msid is None:
        return send_answer(ev, rp.Reply(rp.types.ERR_NOT_IN_CACHE), True)

    # Check if user is a moderator or admin
    try:
        user = db.getUser(id=c_user.id)

        # Check if user is in cooldown (moderators and admins bypass this check)
        if user.rank < RANKS.mod and user.isInCooldown():
            return send_answer(ev, rp.Reply(rp.types.ERR_COOLDOWN, until=user.cooldownUntil), True)

        if user.rank >= RANKS.mod:
            # Moderators can delete directly without warning
            r = core.delete_message(c_user, reply_msid)
        else:
            # Regular users vote to remove
            r = core.user_remove_vote(c_user, reply_msid)
    except KeyError:
        # User not in database, treat as regular user
        r = core.user_remove_vote(c_user, reply_msid)

    send_answer(ev, r, True)


cmd_purgebanned = wrap_core(core.cleanup_messages)


@takesArgument()
def cmd_uncooldown(ev, arg):
    c_user = UserContainer(ev.from_user)

    oid, username = None, None
    if len(arg) < 5:
        oid = arg  # usernames can't be this short -> it's an id
    else:
        username = arg

    send_answer(ev, core.uncooldown_user(c_user, oid, username), True)


@takesArgument(optional=True)
def cmd_blacklist(ev: TMessage, arg):
    c_user = UserContainer(ev.from_user)
    if ev.reply_to_message is None:
        return send_answer(ev, rp.Reply(rp.types.ERR_NO_REPLY), True)

    reply_msid = ch.findMapping(
        ev.from_user.id, ev.reply_to_message.message_id)
    if reply_msid is None:
        return send_answer(ev, rp.Reply(rp.types.ERR_NOT_IN_CACHE), True)
    return send_answer(ev, core.blacklist_user(c_user, reply_msid, arg), True)


@takesArgument()
def cmd_unblacklist(ev: TMessage, arg):
    c_user = UserContainer(ev.from_user)
    arg = arg.lstrip("@")

    oid, username = None, None
    if len(arg) < 5:
        oid = arg  # usernames can't be this short -> it's an id
    else:
        username = arg

    send_answer(ev, core.unblacklist_user(c_user, oid, username), True)


cmd_moderated = wrap_core(core.get_moderated_users)


# Credit system commands
cmd_creditstats = wrap_core(core.get_credit_stats)


@takesArgument()
def cmd_credit(ev: TMessage, arg):
    """Send credits to another user by replying to their message."""
    c_user = UserContainer(ev.from_user)

    if ev.reply_to_message is None:
        return send_answer(ev, rp.Reply(rp.types.ERR_NO_REPLY), True)

    try:
        amount = float(arg)
    except ValueError:
        return send_answer(ev, rp.Reply(rp.types.ERR_CREDITS_INVALID_AMOUNT), True)

    reply_msid = ch.findMapping(
        ev.from_user.id, ev.reply_to_message.message_id)
    if reply_msid is None:
        return send_answer(ev, rp.Reply(rp.types.ERR_NOT_IN_CACHE), True)

    return send_answer(ev, core.send_credits(c_user, reply_msid, amount), True)


@takesArgument()
def cmd_gamblecredits(ev: TMessage, arg):
    """Gamble credits with a 50% chance to double the amount."""
    c_user = UserContainer(ev.from_user)

    try:
        amount = float(arg)
    except ValueError:
        return send_answer(ev, rp.Reply(rp.types.ERR_CREDITS_INVALID_AMOUNT), True)

    return send_answer(ev, core.gamble_credits(c_user, amount), True)


def relay(ev: TMessage):
    # handle commands and voting
    if ev.content_type == "text":
        if ev.text.startswith("/"):
            c, _ = split_command(ev.text)
            if c in registered_commands.keys():
                registered_commands[c](ev)
            return

    # manually handle signing / tripcodes for media since captions don't count for commands
    if not is_forward(ev) and ev.content_type in CAPTIONABLE_TYPES and (ev.caption or "").startswith("/"):
        c, arg = split_command(ev.caption)
        if c == "s":
            return relay_inner(ev, caption_text=arg, signed=True)
        elif c == "t":
            return relay_inner(ev, caption_text=arg, tripcode=True)

    relay_inner(ev)

# relay the message `ev` to other users in the chat
# `caption_text` can be a FormattedMessage that overrides the caption of media
# `signed` and `tripcode` indicate if the message is signed or tripcoded respectively


def relay_inner(ev: TMessage, *, caption_text=None, signed=False, tripcode=False):
    if not is_forward(ev) and ev.content_type == "poll":
        return send_answer(ev, rp.Reply(rp.types.ERR_POLLS_UNSUPPORTED))

    # Apply persistent signing/tripcode settings if not already set
    if not signed and not tripcode and not is_forward(ev):
        try:
            user = db.getUser(id=ev.from_user.id)
            if getattr(user, 'signenabled', False):
                signed = True
            elif getattr(user, 'tsignenabled', False):
                tripcode = True
        except KeyError:
            pass

    is_media = is_forward(ev) or ev.content_type in MEDIA_FILTER_TYPES
    msid = core.prepare_user_message(UserContainer(ev.from_user), calc_spam_score(ev),
                                     is_media=is_media, signed=signed, tripcode=tripcode, message=ev)
    if msid is None or isinstance(msid, rp.Reply):
        # Check if it's a QUESTION filter reply
        if isinstance(msid, rp.Reply) and msid.type == rp.types.ERR_QUESTION_FILTER:
            # Check the sender's preference: if they disabled confirmations, bypass the question prompt
            try:
                pref_user = db.getUser(id=ev.from_user.id)
            except KeyError:
                pref_user = None

            if pref_user is not None and not getattr(pref_user, 'sendconfirm', True):
                # Bypass confirmation and send immediately, but ensure recipients still see vote button
                add_vote_button = True

                # Now prepare and send the message (bypassing the filter)
                user = pref_user
                msg_score = calc_spam_score(ev)

                # Check prerequisites but skip the filter
                if user.isInCooldown():
                    return send_answer(ev, rp.Reply(rp.types.ERR_COOLDOWN, until=user.cooldownUntil), reply_to=True)
                if (signed or tripcode) and not core.enable_signing:
                    return send_answer(ev, rp.Reply(rp.types.ERR_COMMAND_DISABLED), reply_to=True)
                if tripcode and user.tripcode is None:
                    return send_answer(ev, rp.Reply(rp.types.ERR_NO_TRIPCODE), reply_to=True)
                if is_media and user.rank < RANKS.mod and core.media_limit_period is not None:
                    if (datetime.now() - user.joined) < core.media_limit_period:
                        return send_answer(ev, rp.Reply(rp.types.ERR_MEDIA_LIMIT), reply_to=True)

                # Check spam score
                ok = core.spam_scores.increaseSpamScore(user.id, msg_score)
                if not ok:
                    wait_seconds = core.spam_scores.getWaitSeconds(user.id)
                    return send_answer(ev, rp.Reply(rp.types.ERR_SPAMMY, wait_seconds=wait_seconds), reply_to=True)

                # Assign message ID with vote button
                msid2 = ch.assignMessageId(CachedMessage(
                    user.id, needs_vote_button=add_vote_button))

                # Apply text formatting
                ev_tosend = ev
                force_caption = None
                if is_forward(ev):
                    pass  # leave message alone
                elif ev.content_type == "text" or ev.caption is not None or caption_text is not None:
                    fmt = FormattedMessageBuilder(
                        caption_text, ev.caption, ev.text)
                    formatter_replace_links(ev, fmt)
                    formatter_network_links(fmt)
                    if signed:
                        formatter_signed_message(user, fmt)
                    elif tripcode:
                        formatter_tripcoded_message(user, fmt)
                    fmt = fmt.build()
                    # either replace whole message or just the caption
                    if ev.content_type == "text":
                        ev_tosend = fmt or ev_tosend
                    else:
                        force_caption = fmt

                # find out which message is being replied to
                reply_msid = None
                if ev.reply_to_message is not None:
                    reply_msid = ch.findMapping(
                        ev.from_user.id, ev.reply_to_message.message_id)
                    if reply_msid is None:
                        logging.warning(
                            "Message replied to not found in cache")

                # Credit system: earn credits for sending messages
                core.add_credits_for_message(user.id, is_media)

                # relay message to all other users
                logging.debug(
                    "relay() bypass confirmation: msid=%d reply_msid=%r", msid2, reply_msid)
                for user2 in db.iterateUsers():
                    if not user2.isJoined():
                        continue
                    if user2 == user and not user.debugEnabled:
                        ch.saveMapping(user2.id, msid2, ev.message_id)
                        continue

                    send_to_single(ev_tosend, msid2, user2,
                                   reply_msid=reply_msid, force_caption=force_caption)
                return

            # Store the message data so it can be sent later
            pending_data = {
                'ev': ev,
                'caption_text': caption_text,
                'signed': signed,
                'tripcode': tripcode,
                'is_media': is_media,
                'add_vote_button': True  # Messages requiring confirmation get vote button
            }
            ch.savePendingMessage(ev.from_user.id, ev.message_id, pending_data)

            # Send the question with "Send Anyways" button
            markup = telebot.types.InlineKeyboardMarkup()
            button = telebot.types.InlineKeyboardButton(
                text="Send anyways",
                callback_data=f"send_anyways:{ev.from_user.id}:{ev.message_id}"
            )
            markup.add(button)

            # Send the reply with the button
            reply_to_id = ev.message_id

            def f(ev=ev, msid=msid, markup=markup):
                while True:
                    try:
                        bot.send_message(
                            ev.chat.id,
                            rp.formatForTelegram(msid),
                            parse_mode="HTML",
                            reply_to_message_id=reply_to_id,
                            reply_markup=markup
                        )
                    except telebot.apihelper.ApiException as e:
                        retry = check_telegram_exc(e, None)
                        if retry:
                            continue
                        return
                    break

            try:
                user = db.getUser(id=ev.from_user.id)
            except KeyError as e:
                user = None
            put_into_queue(user, None, f)
            return

        # Check if it's a POTENTIALLY_UNWANTED filter reply
        if isinstance(msid, rp.Reply) and msid.type == rp.types.POTENTIALLY_UNWANTED_FILTER:
            user = db.getUser(id=ev.from_user.id)

            # Assign message ID with potentially unwanted flag
            msid2 = ch.assignMessageId(CachedMessage(
                user.id, needs_vote_button=False, is_potentially_unwanted=True))

            # Apply text formatting
            ev_tosend = ev
            force_caption = None
            if is_forward(ev):
                pass  # leave message alone
            elif ev.content_type == "text" or ev.caption is not None or caption_text is not None:
                fmt = FormattedMessageBuilder(
                    caption_text, ev.caption, ev.text)
                formatter_replace_links(ev, fmt)
                formatter_network_links(fmt)
                if signed:
                    formatter_signed_message(user, fmt)
                elif tripcode:
                    formatter_tripcoded_message(user, fmt)
                fmt = fmt.build()
                # either replace whole message or just the caption
                if ev.content_type == "text":
                    ev_tosend = fmt or ev_tosend
                else:
                    force_caption = fmt

            # find out which message is being replied to
            reply_msid = None
            if ev.reply_to_message is not None:
                reply_msid = ch.findMapping(
                    ev.from_user.id, ev.reply_to_message.message_id)
                if reply_msid is None:
                    logging.warning(
                        "Message replied to not found in cache")

            # relay message only to users who have showPotentiallyUnwanted enabled
            logging.debug(
                "relay() potentially unwanted: msid=%d reply_msid=%r", msid2, reply_msid)
            for user2 in db.iterateUsers():
                if not user2.isJoined():
                    continue
                # Skip users who don't want potentially unwanted messages
                if not getattr(user2, 'showPotentiallyUnwanted', False):
                    continue
                if user2 == user and not user.debugEnabled:
                    ch.saveMapping(user2.id, msid2, ev.message_id)
                    continue

                send_to_single(ev_tosend, msid2, user2,
                               reply_msid=reply_msid, force_caption=force_caption)
            return

        # don't relay message, instead reply
        return send_answer(ev, msid, reply_to=True)

    user = db.getUser(id=ev.from_user.id)

    # for signed msgs: check user's forward privacy status first
    # FIXME? this is a possible bottleneck
    if signed:
        tchat = bot.get_chat(user.id)
        if tchat.has_private_forwards:
            return send_answer(ev, rp.Reply(rp.types.ERR_SIGN_PRIVACY))

    # apply text formatting to text or caption (if media)
    ev_tosend = ev
    force_caption = None
    if is_forward(ev):
        pass  # leave message alone
    elif ev.content_type == "text" or ev.caption is not None or caption_text is not None:
        fmt = FormattedMessageBuilder(caption_text, ev.caption, ev.text)
        formatter_replace_links(ev, fmt)
        formatter_network_links(fmt)
        if signed:
            formatter_signed_message(user, fmt)
        elif tripcode:
            formatter_tripcoded_message(user, fmt)
        fmt = fmt.build()
        # either replace whole message or just the caption
        if ev.content_type == "text":
            ev_tosend = fmt or ev_tosend
        else:
            force_caption = fmt

    # find out which message is being replied to
    reply_msid = None
    if ev.reply_to_message is not None:
        reply_msid = ch.findMapping(
            ev.from_user.id, ev.reply_to_message.message_id)
        if reply_msid is None:
            logging.warning("Message replied to not found in cache")

    # relay message to all other users
    logging.debug("relay(): msid=%d reply_msid=%r", msid, reply_msid)
    for user2 in db.iterateUsers():
        if not user2.isJoined():
            continue
        if user2 == user and not user.debugEnabled:
            ch.saveMapping(user2.id, msid, ev.message_id)
            continue

        send_to_single(ev_tosend, msid, user2,
                       reply_msid=reply_msid, force_caption=force_caption)


@takesArgument()
def cmd_s(ev: TMessage, arg):
    ev.text = arg
    relay_inner(ev, signed=True)


@takesArgument()
def cmd_t(ev: TMessage, arg):
    ev.text = arg
    relay_inner(ev, tripcode=True)


def message_reaction(ev: telebot.types.MessageReactionUpdated):
    if ev.chat.type != "private" or ev.user is None:
        return
    c_user = UserContainer(ev.user)

    # Helper to check if a reaction matches any of the given emojis
    def match_emoji(r, emojis):
        return r.type == "emoji" and any(e in r.emoji for e in emojis)

    # Upvote emojis: thumbs up and heart
    upvote_emojis = ["\U0001F44D", "\u2764", "\U0001F9E1", "\U0001F49B", "\U0001F49A", "\U0001F499", "\U0001F49C",
                     "\U0001F5A4", "\U0001F90D", "\U0001F90E", "\U0001F497", "\U0001F495", "\U0001F493", "\U0001F498", "\U00002764"]
    # Downvote emoji: thumbs down
    downvote_emojis = ["\U0001F44E"]

    def match_upvote(r): return match_emoji(r, upvote_emojis)
    def match_downvote(r): return match_emoji(r, downvote_emojis)

    # Check for new upvote reaction
    if not any(match_upvote(r) for r in ev.old_reaction) and any(match_upvote(r) for r in ev.new_reaction):
        # make up a Message so the reply code can work as usual
        fake_ev = telebot.types.Message(
            ev.message_id, ev.user, 0, ev.chat, "dummy", {}, "")
        reply_msid = ch.findMapping(ev.chat.id, ev.message_id)
        if reply_msid is None:
            return send_answer(fake_ev, rp.Reply(rp.types.ERR_NOT_IN_CACHE), True)
        return send_answer(fake_ev, core.give_vote(c_user, reply_msid), True)

    # Check for new downvote reaction
    if not any(match_downvote(r) for r in ev.old_reaction) and any(match_downvote(r) for r in ev.new_reaction):
        fake_ev = telebot.types.Message(
            ev.message_id, ev.user, 0, ev.chat, "dummy", {}, "")
        reply_msid = ch.findMapping(ev.chat.id, ev.message_id)
        if reply_msid is None:
            return send_answer(fake_ev, rp.Reply(rp.types.ERR_NOT_IN_CACHE), True)
        return send_answer(fake_ev, core.take_vote(c_user, reply_msid), True)


def handle_callback_query(call: telebot.types.CallbackQuery):
    """Handle inline button callbacks (e.g., vote to delete)"""
    if call.message.chat.type != "private":
        return

    c_user = UserContainer(call.from_user)

    # Parse callback data
    if call.data.startswith("vote_delete:"):
        try:
            # Extract msid from callback data
            _, msid_str = call.data.split(":", 1)
            msid = int(msid_str)

            # Check if user is in cooldown
            try:
                user = db.getUser(id=c_user.id)
                if user.isInCooldown():
                    bot.answer_callback_query(
                        call.id,
                        text=f"You are in cooldown until {user.cooldownUntil.strftime('%Y-%m-%d %H:%M:%S')}",
                        show_alert=True
                    )
                    return
            except KeyError:
                # User not in database, allow to proceed
                pass

            # Find the msid in the user's message mappings
            # The callback is on the user's own copy of the message
            reply_msid = ch.findMapping(
                call.message.chat.id, call.message.message_id)

            if reply_msid is None:
                # If not found in mapping, use the msid from callback data
                reply_msid = msid

            # Call the user_remove_vote function
            result = core.user_remove_vote(c_user, reply_msid)

            # Remove the button from the message
            try:
                bot.edit_message_reply_markup(
                    chat_id=call.message.chat.id,
                    message_id=call.message.message_id,
                    reply_markup=None
                )
            except Exception as e:
                logging.error("Error removing vote button: %s", e)

            # Answer the callback query to remove the loading state
            if result is not None:
                # Check if threshold was reached (SUCCESS means message will be deleted)
                if result.type == rp.types.SUCCESS:
                    bot.answer_callback_query(
                        call.id, text="Message will be deleted")
                else:
                    # Vote registered but threshold not reached yet
                    bot.answer_callback_query(call.id, text="Vote registered")

                    # Send a message showing how many votes are left
                    try:
                        sent_msg = bot.send_message(
                            call.message.chat.id,
                            rp.formatForTelegram(result),
                            parse_mode="HTML",
                            reply_to_message_id=call.message.message_id
                        )
                        # Store this vote count message ID so it can be deleted later
                        ch.saveVoteCountMessage(
                            reply_msid, call.message.chat.id, sent_msg.message_id)
                    except Exception as e:
                        logging.error(
                            "Error sending vote count message: %s", e)
            else:
                bot.answer_callback_query(call.id)

        except Exception as e:
            logging.error("Error handling vote_delete callback: %s", e)
            bot.answer_callback_query(call.id, text="Error processing vote")

    elif call.data.startswith("send_anyways:"):
        try:
            # Extract user_id and message_id from callback data
            parts = call.data.split(":")
            if len(parts) != 3:
                bot.answer_callback_query(
                    call.id, text="Invalid callback data")
                return

            _, user_id_str, message_id_str = parts
            user_id = int(user_id_str)
            message_id = int(message_id_str)

            # Verify the user clicking the button is the same as the one who sent the message
            if call.from_user.id != user_id:
                bot.answer_callback_query(
                    call.id, text="This is not your message")
                return

            # Retrieve the pending message
            pending_data = ch.getPendingMessage(user_id, message_id)
            if pending_data is None:
                bot.answer_callback_query(call.id, text="Message expired")
                return

            # Delete the pending message from cache
            ch.deletePendingMessage(user_id, message_id)

            # Delete the question message
            try:
                bot.delete_message(call.message.chat.id,
                                   call.message.message_id)
            except Exception as e:
                logging.error("Error deleting question message: %s", e)

            # Answer the callback query
            bot.answer_callback_query(call.id, text="Sending message...")

            # Extract the original message data
            ev = pending_data['ev']
            caption_text = pending_data['caption_text']
            signed = pending_data['signed']
            tripcode = pending_data['tripcode']
            is_media = pending_data['is_media']
            add_vote_button = pending_data.get('add_vote_button', False)

            # Now prepare and send the message (bypassing the filter)
            user = db.getUser(id=user_id)
            msg_score = calc_spam_score(ev)

            # Check prerequisites but skip the filter
            if user.isInCooldown():
                return send_answer(ev, rp.Reply(rp.types.ERR_COOLDOWN, until=user.cooldownUntil), reply_to=True)
            if (signed or tripcode) and not core.enable_signing:
                return send_answer(ev, rp.Reply(rp.types.ERR_COMMAND_DISABLED), reply_to=True)
            if tripcode and user.tripcode is None:
                return send_answer(ev, rp.Reply(rp.types.ERR_NO_TRIPCODE), reply_to=True)
            if is_media and user.rank < RANKS.mod and core.media_limit_period is not None:
                if (datetime.now() - user.joined) < core.media_limit_period:
                    return send_answer(ev, rp.Reply(rp.types.ERR_MEDIA_LIMIT), reply_to=True)

            # Check spam score
            ok = core.spam_scores.increaseSpamScore(user.id, msg_score)
            if not ok:
                wait_seconds = core.spam_scores.getWaitSeconds(user.id)
                return send_answer(ev, rp.Reply(rp.types.ERR_SPAMMY, wait_seconds=wait_seconds), reply_to=True)

            # Assign message ID with vote button if needed
            msid = ch.assignMessageId(CachedMessage(
                user.id, needs_vote_button=add_vote_button))

            # Apply text formatting
            ev_tosend = ev
            force_caption = None
            if is_forward(ev):
                pass  # leave message alone
            elif ev.content_type == "text" or ev.caption is not None or caption_text is not None:
                fmt = FormattedMessageBuilder(
                    caption_text, ev.caption, ev.text)
                formatter_replace_links(ev, fmt)
                formatter_network_links(fmt)
                if signed:
                    formatter_signed_message(user, fmt)
                elif tripcode:
                    formatter_tripcoded_message(user, fmt)
                fmt = fmt.build()
                # either replace whole message or just the caption
                if ev.content_type == "text":
                    ev_tosend = fmt or ev_tosend
                else:
                    force_caption = fmt

            # find out which message is being replied to
            reply_msid = None
            if ev.reply_to_message is not None:
                reply_msid = ch.findMapping(
                    ev.from_user.id, ev.reply_to_message.message_id)
                if reply_msid is None:
                    logging.warning("Message replied to not found in cache")

            # Credit system: earn credits for sending messages
            core.add_credits_for_message(user.id, is_media)

            # relay message to all other users
            logging.debug(
                "relay() after confirmation: msid=%d reply_msid=%r", msid, reply_msid)
            for user2 in db.iterateUsers():
                if not user2.isJoined():
                    continue
                if user2 == user and not user.debugEnabled:
                    ch.saveMapping(user2.id, msid, ev.message_id)
                    continue

                send_to_single(ev_tosend, msid, user2,
                               reply_msid=reply_msid, force_caption=force_caption)

        except Exception as e:
            logging.error("Error handling send_anyways callback: %s", e)
            bot.answer_callback_query(call.id, text="Error processing request")

    elif call.data.startswith("hide_potentially_unwanted:"):
        try:
            # Extract user_id from callback data
            parts = call.data.split(":")
            if len(parts) != 2:
                bot.answer_callback_query(
                    call.id, text="Invalid callback data")
                return

            _, target_user_id_str = parts
            target_user_id = int(target_user_id_str)

            # Verify the user clicking the button is the intended recipient
            if call.from_user.id != target_user_id:
                bot.answer_callback_query(
                    call.id, text="This button is not for you")
                return

            # Toggle off potentially unwanted messages for this user
            try:
                with db.modifyUser(id=target_user_id) as user:
                    user.showPotentiallyUnwanted = False
                bot.answer_callback_query(
                    call.id, text="You will no longer receive potentially unwanted messages. Use /togglepotentiallyunwanted to re-enable.")
            except KeyError:
                bot.answer_callback_query(
                    call.id, text="User not found")
                return

            # Remove the button from the message
            try:
                bot.edit_message_reply_markup(
                    call.message.chat.id,
                    call.message.message_id,
                    reply_markup=None
                )
            except Exception as e:
                logging.error("Error removing button: %s", e)

        except Exception as e:
            logging.error(
                "Error handling hide_potentially_unwanted callback: %s", e)
            bot.answer_callback_query(call.id, text="Error processing request")

    else:
        # Unknown callback data
        bot.answer_callback_query(call.id)
