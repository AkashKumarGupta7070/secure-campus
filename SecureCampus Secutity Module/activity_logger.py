from datetime import datetime

def log_activity(ip, endpoint, status, result):

    log = f"{datetime.now()} | {ip} | {endpoint} | {status} | {result}"

    with open("activity.log","a") as f:
        f.write(log + "\n")                                                                                                                                                
