import logging
import itertools
from datetime import datetime, timedelta
from threading import RLock
from typing import Optional, Sequence, Set, Iterator, Dict

from .globals import *


class CachedMessage():
    __slots__ = ('user_id', 'time', 'warned', 'upvoted', 'downvoted',
                 'remove_votes', 'needs_vote_button')
    user_id: Optional[int]
    time: datetime
    warned: bool
    upvoted: Set[int]
    downvoted: Set[int]
    remove_votes: Set[int]
    needs_vote_button: bool

    def __init__(self, user_id=None, needs_vote_button=False):
        self.user_id = user_id  # who has sent this message
        self.time = datetime.now()  # when was this message created?
        self.warned = False  # was the user warned for this message?
        self.upvoted = set()  # user ids that have given this message karma
        self.downvoted = set()  # user ids that have taken karma from this message
        self.remove_votes = set()  # user ids that have voted to remove this message
        # should this message have a delete vote button?
        self.needs_vote_button = needs_vote_button

    def isExpired(self):
        return datetime.now() >= self.time + timedelta(hours=MESSAGE_EXPIRE_HOURS)

    def hasUpvoted(self, user):
        return user.id in self.upvoted

    def addUpvote(self, user):
        self.upvoted.add(user.id)

    def hasDownvoted(self, user):
        return user.id in self.downvoted

    def addDownvote(self, user):
        self.downvoted.add(user.id)


class Cache():
    lock: RLock
    counter: Iterator[int]
    msgs: Dict[int, CachedMessage]
    idmap: Dict[int, Dict[int, object]]
    pending_messages: Dict[int, object]  # user_id -> pending message data
    # msid -> dict(user_id -> message_id)
    vote_count_messages: Dict[int, Dict[int, int]]

    def __init__(self):
        self.lock = RLock()
        self.counter = itertools.count()
        self.msgs = {}  # dict(msid -> CachedMessage)
        self.idmap = {}  # dict(uid -> dict(msid -> opaque))
        self.pending_messages = {}  # dict(uid -> pending message data)
        # dict(msid -> dict(user_id -> vote_count_message_id))
        self.vote_count_messages = {}

    def assignMessageId(self, cm: CachedMessage) -> int:
        with self.lock:
            ret = next(self.counter)
            self.msgs[ret] = cm
        return ret

    def getMessage(self, msid: int) -> CachedMessage:
        with self.lock:
            return self.msgs.get(msid, None)

    def iterateMessages(self, functor):
        with self.lock:
            for msid, cm in self.msgs.items():
                functor(msid, cm)

    # get user-specific mapping by key
    def getMapping(self, uid: int, msid: int) -> object:
        with self.lock:
            t = self.idmap.get(uid, None)
            if t is not None:
                return t.get(msid, None)
    # save user-specific mapping

    def saveMapping(self, uid: int, msid: int, data: object):
        with self.lock:
            if uid not in self.idmap.keys():
                self.idmap[uid] = {}
            self.idmap[uid][msid] = data
    # find user-specific mapping by value (linear search)

    def findMapping(self, uid: int, data: object) -> Optional[int]:
        with self.lock:
            t = self.idmap.get(uid, None)
            if t is not None:
                gen = (msid for msid, _data in t.items() if _data == data)
                return next(gen, None)
    # delete all user-specific mappings by key

    def deleteMappings(self, msid: int):
        with self.lock:
            for d in self.idmap.values():
                d.pop(msid, None)

    def savePendingMessage(self, uid: int, message_id: int, message_data: object):
        """Store a pending message for a user (for QUESTION filter action)

        Args:
            uid: User ID
            message_id: The original message ID from Telegram
            message_data: The message data to store
        """
        with self.lock:
            key = (uid, message_id)
            self.pending_messages[key] = message_data

    def getPendingMessage(self, uid: int, message_id: int) -> object:
        """Get a pending message for a user

        Args:
            uid: User ID
            message_id: The original message ID from Telegram
        """
        with self.lock:
            key = (uid, message_id)
            return self.pending_messages.get(key, None)

    def deletePendingMessage(self, uid: int, message_id: int):
        """Delete a pending message for a user

        Args:
            uid: User ID
            message_id: The original message ID from Telegram
        """
        with self.lock:
            key = (uid, message_id)
            self.pending_messages.pop(key, None)

    def saveVoteCountMessage(self, msid: int, uid: int, message_id: int):
        """Store a vote count message ID for a specific msid and user"""
        with self.lock:
            if msid not in self.vote_count_messages:
                self.vote_count_messages[msid] = {}
            self.vote_count_messages[msid][uid] = message_id

    def getVoteCountMessages(self, msid: int) -> Dict[int, int]:
        """Get all vote count message IDs for a specific msid"""
        with self.lock:
            return self.vote_count_messages.get(msid, {}).copy()

    def deleteVoteCountMessages(self, msid: int):
        """Delete all vote count message records for a specific msid"""
        with self.lock:
            self.vote_count_messages.pop(msid, None)

    def expire(self) -> Sequence[int]:
        ids = set()
        with self.lock:
            for msid in list(self.msgs.keys()):
                if not self.msgs[msid].isExpired():
                    continue
                ids.add(msid)
                # delete message itself and from mappings
                del self.msgs[msid]
                self.deleteMappings(msid)
                # also delete vote count messages
                self.deleteVoteCountMessages(msid)
        if len(ids) > 0:
            logging.debug("Expired %d entries from cache", len(ids))
        return ids
