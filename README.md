secretlounge-ng
---------------

A rewrite of [secretlounge](https://web.archive.org/web/20200920053736/https://github.com/6697/secretlounge), a bot to make an anonymous group chat on Telegram.

The bot accepts messages, pictures, videos, etc. from any user and relays it to all other active users without revealing the author.

## Setup

You will need a Linux server or computer with Python 3 installed and access to the command line.

```bash
pip3 install -e .
cp config.yaml.example config.yaml
# Edit config.yaml with your favorite text editor
./secretlounge-ng
```

To run the bot in the background use a systemd service (preferred) or screen/tmux.

Note that you can also install it as a normal Python module and run it from anywhere
like `python3 -m secretlounge_ng`, which I won't explain here.

## @BotFather Setup

Message [@BotFather](https://t.me/BotFather) and configure your bot as follows:

* `/setprivacy`: enabled
* `/setjoingroups`: disabled
* `/setcommands`: paste the command list below

### Command list

```
start - Join the chat (start receiving messages)
stop - Leave the chat (stop receiving messages)
users - Find out how many users are in the chat
info - Get info about your account
sign - Sign a message with your username
s - Alias of sign
tsign - Sign a message with your tripcode
t - Alias of tsign
remove - Vote to remove a message collectively (reply to a message to remove)
motd - Show the welcome message
privacy - Show privacy policy
version - Get version & source code of this bot
modhelp - Show commands available to moderators
adminhelp - Show commands available to admins
toggledebug - Toggle debug mode (sends back all messages to you)
togglekarma - Toggle karma notifications
tripcode - Show or set the tripcode for your messages
```

## Custom Message Filtering

You can implement custom filters to control which messages are forwarded to the chat. This is useful for:
- Blocking spam or abusive content
- Requiring minimum karma/trust before allowing certain message types
- Time-based restrictions
- Rate limiting
- Any custom logic you can implement in Python

### Setup

1. **Create a filter file** (or copy the template):
   ```bash
   cp message_filter.py my_filter.py
   ```

2. **Edit your filter logic**:
   ```python
   def message_filter(user, is_media=False, signed=False, tripcode=False):
       # Block users with very low karma
       if user.karma < -20:
           return False
       
       # Block media from users with warnings
       if is_media and user.warnings > 2:
           return False
       
       # Allow all other messages
       return True
   ```

3. **Enable in config.yaml**:
   ```yaml
   message_filter: "./my_filter.py"
   ```

4. **Restart the bot** - The filter is loaded automatically on startup

### Available User Properties

Your filter function receives a `user` object with these properties:
- `user.id` - Telegram user ID
- `user.username` - Username
- `user.karma` - Karma score
- `user.warnings` - Number of warnings
- `user.rank` - User rank (0=regular, 10=mod, 100=admin)
- `user.joined` - DateTime when user joined
- `user.isInCooldown()` - Check if in cooldown
- `user.isBlacklisted()` - Check if blacklisted

See `message_filter_example.py` for 8+ different example implementations including rate limiting, time-based filters, and more.

## FAQ

1. **How do I unban a blacklisted user from my bot?**

To unban someone you need their Telegram User ID (preferred) or username/profile name.
If you have a name you can use `./util/blacklist.py find` to search your bot's database for the user record.

You can then run `./util/blacklist.py unban 12345678` to remove the ban.

2. **How do I demote someone I promoted to mod/admin at some point?**

If you already have an User ID in mind, proceed below.
Otherwise you can either use the find utility like explained above or run
`./util/perms.py list` to list all users with elevated rank.

Simply run `./util/perms.py set 12345678 user` to reset this users privileges.

You can also grant an user higher privileges by exchanging the last argument with "*mod*" or "*admin*".

3. **What is the suggested setup to run multiple bots?**

The `blacklist.py` and `perms.py` script, including advanced functions like blacklist syncing
(`./util/blacklist.py sync`), support a structure as follows where each bot
has its own subdirectory:

```
root folder
\-- bot1
  \-- db.sqlite
  \-- config.yaml
\-- bot2
  \-- db.sqlite
  \-- ...
\-- ...
\-- README.md
\-- secretlounge-ng
```

4. **Is this bot really anonymous?**

When using the source in this repository*¹*, unless you reveal yourself,
ordinary users in the bot have zero possibilities of discovering your Telegram user.

Mods and admins in the bot can not see your Telegram user, instead they can tell authors
of recent messages apart through a pseudo-random ID returned by the `/info` command.
This ID changes every 24 hours, messages also expire from the cache after 30 hours*²*
(or if secretlounge-ng is restarted) meaning that they become unable to be deleted
or their authors determined.

People with access to the server the bot runs on have no direct, but a variety of
indirect ways to determine who wrote a particular message.

*¹*: It is impossible to ascertain this from afar. You have to trust the bot owner either way.

*²*: If you say something identifiable every 30 hours, you can reasonably be tracked for longer periods.
This quickly becomes infeasible to perform by hand with larger message volumes and user populations.

All of these assessments presume a sufficient user population in the bot so that anyone could blend in.

5. **Why don't polls work?**

Telegram bots are able to create new polls and forward messages (including authorship),
but they can't forward the poll itself as with other message types.
Working around this is possible with some disadvantages, but has not been implemented yet.

6. **Is this code maintained?**

This codebase is in active use [over here](https://t.me/s/secretloungeproject).
Updates are made either if there's something broken or when the author feels like it.

## Notable forks

* [CatLounge](https://github.com/CatLounge/catlounge-ng-meow) - has numerous new features including specifying cooldown time
* [Furry fork](https://github.com/dogmike/secretlounge-ng) - not sure, but there's a bunch of things
