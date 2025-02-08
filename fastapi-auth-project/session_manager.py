import redis
import json
from datetime import datetime, timedelta


# Connect to Redis
redis_client = redis.Redis(host="localhost", port=6379, db=0, decode_responses=True)

SESSION_EXPIRY_MINUTES = 30  # Session timeout duration

def create_session(email: str, token: str):
    expiry_time = datetime.utcnow() + timedelta(minutes=SESSION_EXPIRY_MINUTES)
    redis_client.setex(email, SESSION_EXPIRY_MINUTES * 60, json.dumps({"token": token, "expiry": expiry_time.isoformat()}))

def get_session(email: str):
    session_data = redis_client.get(email)
    if not session_data:
        return None

    session = json.loads(session_data)
    if datetime.utcnow() > datetime.fromisoformat(session["expiry"]):
        redis_client.delete(email)
        return None
    
    return session["token"]

def delete_session(email: str):
    redis_client.delete(email)
