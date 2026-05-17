from time import time

# user -> metadata
blocked_users = {}


# -------------------------
# BLOCK USER
# -------------------------
def block_user(user, reason="UNKNOWN"):

    if not user:
        return

    blocked_users[user] = {
        "time": time(),
        "reason": reason
    }


# -------------------------
# CHECK USER BLOCK
# -------------------------
def is_user_blocked(user):
    return user in blocked_users


# -------------------------
# UNBLOCK USER
# -------------------------
def unblock_user(user):
    blocked_users.pop(user, None)


# -------------------------
# GET ALL BLOCKED USERS
# -------------------------
def get_blocked_users():

    return [
        {
            "user": user,
            "reason": data["reason"],
            "blocked_time": data["time"]
        }
        for user, data in blocked_users.items()
    ]


