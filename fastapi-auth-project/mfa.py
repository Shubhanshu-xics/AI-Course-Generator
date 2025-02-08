import pyotp
import redis
import json
from datetime import datetime, timedelta

# Connect to Redis
redis_client = redis.Redis(host="localhost", port=6379, db=1, decode_responses=True)

OTP_EXPIRY_MINUTES = 5  # OTP expiry duration

def generate_otp(email: str):
    totp = pyotp.TOTP(pyotp.random_base32(), interval=OTP_EXPIRY_MINUTES * 60)
    otp_code = totp.now()
    
    expiry_time = datetime.utcnow() + timedelta(minutes=OTP_EXPIRY_MINUTES)
    redis_client.setex(email, OTP_EXPIRY_MINUTES * 60, json.dumps({"otp": otp_code, "expiry": expiry_time.isoformat()}))
    
    return otp_code  # Normally, send via email/SMS

def verify_otp(email: str, otp: str):
    stored_data = redis_client.get(email)
    if not stored_data:
        return False

    otp_data = json.loads(stored_data)
    expiry_time = datetime.fromisoformat(otp_data["expiry"])
    
    if datetime.utcnow() > expiry_time or otp_data["otp"] != otp:
        redis_client.delete(email)
        return False
    
    redis_client.delete(email)
    return True
