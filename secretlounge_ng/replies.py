import re
from string import Formatter

from .globals import *


class NumericEnum(Enum):
    def __init__(self, names):
        d = {name: i for i, name in enumerate(names)}
        super().__init__(d)


class CustomFormatter(Formatter):
    def convert_field(self, value, conversion):
        if conversion == "x":  # escape
            return escape_html(value)
        elif conversion == "t":  # date[t]ime
            return format_datetime(value)
        elif conversion == "d":  # time[d]elta
            return format_timedelta(value)
        return super().convert_field(value, conversion)

# definition of reply class and types


class Reply():
    def __init__(self, type_, **kwargs):
        self.type = type_
        self.kwargs = kwargs


types = NumericEnum([
    "CUSTOM",
    "SUCCESS",
    "BOOLEAN_CONFIG",

    "CHAT_JOIN",
    "CHAT_LEAVE",
    "USER_IN_CHAT",
    "USER_NOT_IN_CHAT",
    "GIVEN_COOLDOWN",
    "MESSAGE_DELETED",
    "DELETION_QUEUED",
    "REMOVE_VOTE_REGISTERED",
    "REMOVE_THRESHOLD_REACHED",
    "PROMOTED_MOD",
    "PROMOTED_ADMIN",
    "COOLDOWN_REMOVED",
    "UNBLACKLISTED",
    "KARMA_THANK_YOU",
    "KARMA_NOTIFICATION",
    "KARMA_TAKEN",
    "KARMA_NEGATIVE_NOTIFICATION",
    "TRIPCODE_INFO",
    "TRIPCODE_SET",

    "ERR_COMMAND_DISABLED",
    "ERR_NO_REPLY",
    "ERR_NOT_IN_CACHE",
    "ERR_NO_USER",
    "ERR_NO_USER_BY_ID",
    "ERR_ALREADY_WARNED",
    "ERR_NOT_IN_COOLDOWN",
    "ERR_NOT_BLACKLISTED",
    "ERR_COOLDOWN",
    "ERR_BLACKLISTED",
    "ERR_ALREADY_UPVOTED",
    "ERR_UPVOTE_OWN_MESSAGE",
    "ERR_ALREADY_DOWNVOTED",
    "ERR_DOWNVOTE_OWN_MESSAGE",
    "ERR_SPAMMY",
    "ERR_SPAMMY_SIGN",
    "ERR_SPAMMY_REMOVE",
    "ERR_GLOBAL_REMOVE_LIMIT",
    "ERR_SIGN_PRIVACY",
    "ERR_INVALID_TRIP_FORMAT",
    "ERR_NO_TRIPCODE",
    "ERR_MEDIA_LIMIT",
    "ERR_POLLS_UNSUPPORTED",
    "ERR_BLOCKED_BY_FILTER",
    "ERR_QUESTION_FILTER",

    "USER_INFO",
    "USER_INFO_MOD",
    "USERS_INFO",
    "USERS_INFO_EXTENDED",
    "MODERATED_LIST",

    "HELP",
])

# formatting of these as user-readable text


def em(s):
    # make commands clickable by excluding them from the formatting
    s = re.sub(r'[^a-z0-9_-]/[A-Za-z]+\b', r'</em>\g<0><em>', s)
    return "<em>" + s + "</em>"


def smiley(n):
    if n <= 0:
        return ":)"
    elif n == 1:
        return ":|"
    elif n <= 3:
        return ":/"
    else:
        return ":("


format_strs = {
    types.CUSTOM: "{text}",
    types.SUCCESS: "☑",
    types.BOOLEAN_CONFIG: lambda enabled, **_:
    "<b>{description!x}</b>: " + (enabled and "enabled" or "disabled"),

        types.CHAT_JOIN: em("You joined the chat!"),
        types.CHAT_LEAVE: em("You left the chat!"),
        types.USER_IN_CHAT: em("You're already in the chat."),
        types.USER_NOT_IN_CHAT: em("You're not in the chat yet. Use /start to join!"),
        types.GIVEN_COOLDOWN: lambda deleted, **_:
        em("You've been warned for this message. A cooldown of {duration!d} has been given" +
           (deleted and " (one or more messages also deleted)" or "")),
        types.MESSAGE_DELETED:
        em("Your message has been deleted. No cooldown has been "
           "given this time, but refrain from posting it again."),
        types.DELETION_QUEUED: em("{count} messages matched, deletion was queued."),
        types.REMOVE_VOTE_REGISTERED: lambda votes_left, **_:
        em("{votes_left} " + ("vote" if votes_left ==
                              1 else "votes") + " left to remove this message."),
        types.REMOVE_THRESHOLD_REACHED: em("Message removal threshold reached. Message will be deleted."),
        types.PROMOTED_MOD: em("You've been promoted to moderator."),
        types.PROMOTED_ADMIN: em("You've been promoted to admin."),
        types.COOLDOWN_REMOVED: em("Your cooldown has been removed by a moderator. You can chat again!"),
        types.UNBLACKLISTED: em("You've been removed from the blacklist. Welcome back!"),
        types.KARMA_THANK_YOU: em("You just gave this user some sweet karma, awesome!"),
        types.KARMA_NOTIFICATION:
        em("You've just been given sweet karma! (check /info to see your karma" +
           " or /toggleKarma to turn these notifications off)"),
        types.KARMA_TAKEN: em("You've taken karma from this user."),
        types.KARMA_NEGATIVE_NOTIFICATION:
        em("Someone took karma from you. (check /info to see your karma" +
           " or /toggleKarma to turn these notifications off)"),
        types.TRIPCODE_INFO: lambda tripcode, **_:
        "<b>tripcode</b>: " +
        ("<code>{tripcode!x}</code>" if tripcode is not None else "unset"),
        types.TRIPCODE_SET: em("Tripcode set. It will appear as: ") + "<b>{tripname!x}</b> <code>{tripcode!x}</code>",

        types.ERR_COMMAND_DISABLED: em("This command has been disabled."),
        types.ERR_NO_REPLY: em("You need to reply to a message to use this command."),
        types.ERR_NOT_IN_CACHE: em("Message not found in cache... (" + str(MESSAGE_EXPIRE_HOURS) + "h passed or bot was restarted)"),
        types.ERR_NO_USER: em("No user found by that name!"),
        types.ERR_NO_USER_BY_ID: em("No user found by that id! Note that all ids rotate every 24 hours."),
        types.ERR_COOLDOWN: em("Your cooldown expires at {until!t}"),
        types.ERR_ALREADY_WARNED: em("A warning has already been issued for this message."),
        types.ERR_NOT_IN_COOLDOWN: em("This user is not in a cooldown right now."),
        types.ERR_NOT_BLACKLISTED: em("This user is not blacklisted."),
        types.ERR_BLACKLISTED: lambda reason, contact, **_:
        em("You've been blacklisted. If this is an error, contact a mod or admin" + (reason and " for {reason!x}" or "")) +
        (em("\ncontact:") + " {contact}" if contact else ""),
        types.ERR_ALREADY_UPVOTED: em("You have already upvoted this message."),
        types.ERR_UPVOTE_OWN_MESSAGE: em("You can't upvote your own message."),
        types.ERR_ALREADY_DOWNVOTED: em("You have already downvoted this message."),
        types.ERR_DOWNVOTE_OWN_MESSAGE: em("You can't downvote your own message."),
        types.ERR_SPAMMY: em("Your message has not been sent. Avoid sending messages too fast, try again later."),
        types.ERR_SPAMMY_SIGN: em("Your message has not been sent. Avoid using /sign too often, try again later."),
        types.ERR_SPAMMY_REMOVE: em("You are using /remove too often. Please wait before voting to remove another message."),
        types.ERR_SIGN_PRIVACY: em("Your account privacy settings prevent usage of the sign feature. Enable linked forwards first."),
        types.ERR_INVALID_TRIP_FORMAT:
        em("Given tripcode is not valid, the format is ") +
        "<code>name#pass</code>" + em("."),
        types.ERR_NO_TRIPCODE: em("You don't have a tripcode set."),
        types.ERR_MEDIA_LIMIT: em("You can't send media or forward messages at this time, try again later."),
        types.ERR_POLLS_UNSUPPORTED: em("Your message has not been sent. Polls are not supported, sorry."),
        types.ERR_BLOCKED_BY_FILTER: em("Your message has been blocked by the message filter."),
        types.ERR_QUESTION_FILTER: em("Are you sure, this is according to rules (check /motd)?"),

        types.USER_INFO: lambda warnings, cooldown, **_:
        "<b>id</b>: {id}, <b>username</b>: {username!x}, <b>rank</b>: {rank_i} ({rank})\n" +
        "<b>karma</b>: {karma}\n" +
        "<b>warnings</b>: {warnings} " + smiley(warnings) +
        (" (one warning will be removed on {warnExpiry!t})" if warnings > 0 else "") + ", " +
        "<b>cooldown</b>: " +
        (cooldown and "yes, until {cooldown!t}" or "no"),
        types.USER_INFO_MOD: lambda cooldown, **_:
        "<b>id</b>: {id}, <b>username</b>: anonymous, <b>rank</b>: n/a, " +
        "<b>karma bracket</b>: {karma}\n" +
        "<b>cooldown</b>: " +
        (cooldown and "yes, until {cooldown!t}" or "no"),
        types.USERS_INFO: "<b>{count}</b> <i>users</i>",
        types.USERS_INFO_EXTENDED:
        "<b>{active}</b> <i>active</i>, {inactive} <i>inactive and</i> " +
        "{blacklisted} <i>blacklisted users</i> (<i>total</i>: {total})",
        types.MODERATED_LIST: "{text}",

        types.HELP:
        "<b>Available Commands:</b>\n"
        "\n"
        "<b>Basic Commands:</b>\n"
        "  /start - Join the lounge\n"
        "  /stop - Leave the lounge\n"
        "  /help - Show this help message\n"
        "  /info - Get information about yourself\n"
        "  /users - Get count of active users\n"
        "  /motd - View the Message of the Day\n"
        "\n"
        "<b>Messaging Commands:</b>\n"
        "  /remove - Vote to remove a message\n"
        "  /s - Sign your message with your username\n"
        "  /tripcode - Set your tripcode for pseudo-anonymous identification\n"
        "  /t - Sign your message with your tripcode\n"
        "  React to a message with 👍, ❤️ or 👎 - Give or take karma from the user\n"
        "\n"
        "<b>Settings / Toggles:</b>\n"
        "  /toggledebug - Toggle debug messages you receive from the bot\n"
        "  /togglekarma - Toggle karma notifications\n"
        "  /sendconfirm - Toggle confirmation prompts for flagged messages\n"
        "  /votebutton - Toggle vote/delete buttons on received messages\n"
        "  /toggles - Toggle auto-signing for all your messages\n"
        "  /togglet - Toggle auto-tripcode for all your messages\n"
        "\n"
        "<b>Moderation:</b>\n"
        "  /warn - Warn the user (cooldown)\n"
        "  /delete - Delete message and warn user\n"
        "  /modsay - Send official moderator message\n"
        "  /moderated - List users in cooldown or blacklisted\n"
        "  /blacklist [reason] - Blacklist user\n"
        "  /unblacklist - Remove user from blacklist\n"
        "  /uncooldown - Remove cooldown from user\n"
        "  /mod - Promote user to moderator\n"
        "  /admin - Promote user to admin\n"
        "  /adminsay - Send official admin message\n"
        "  /motd - Set welcome message\n"
        "  /purgebanned - Delete all messages from banned users\n",
}

localization = {}


def formatForTelegram(m):
    s = localization.get(m.type)
    if s is None:
        s = format_strs[m.type]
    if type(s).__name__ == "function":
        s = s(**m.kwargs)
    cls = localization.get("_FORMATTER_", CustomFormatter)
    return cls().format(s, **m.kwargs)
