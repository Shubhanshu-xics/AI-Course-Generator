 
from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from database import SessionLocal, engine, Base
from models import User
from schemas import UserCreate, UserResponse
from security import hash_password
from schemas import UserLogin
from security import verify_password, create_access_token
from security import get_current_user
from session_manager import create_session, get_session, delete_session
from mfa import generate_otp, verify_otp
from social_auth import get_oauth_url, get_user_info
from slowapi import Limiter
from slowapi.util import get_remote_address
from starlette.requests import Request



app = FastAPI()

Base.metadata.create_all(bind=engine)

limiter = Limiter(key_func=get_remote_address)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/register", response_model=UserResponse)
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_password = hash_password(user.password)
    new_user = User(email=user.email, username=user.username, password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user




@app.post("/login")
@limiter.limit("5/minute")
def login_user(request: Request, user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user or not verify_password(user.password, db_user.password):
        raise HTTPException(status_code=400, detail="Invalid email or password")
    
    access_token = create_access_token({"sub": db_user.email})
    create_session(db_user.email, access_token)
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/logout")
def logout_user(user: str = Depends(get_current_user)):
    delete_session(user)
    return {"message": "Logged out successfully"}


@app.get("/session")
def get_user_session(user: str = Depends(get_current_user)):
    session = get_session(user)
    if not session:
        raise HTTPException(status_code=401, detail="Session expired or not found")
    return {"message": "Session is active", "token": session}



@app.post("/mfa/generate")
def generate_mfa_otp(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user:
        raise HTTPException(status_code=400, detail="User not found")

    otp = generate_otp(db_user.email)
    
    # Normally, send OTP via email/SMS (for now, return it in response)
    return {"message": "OTP sent", "otp": otp}  


@app.post("/mfa/verify")
def verify_mfa_otp(email: str, otp: str):
    if verify_otp(email, otp):
        return {"message": "MFA verification successful"}
    raise HTTPException(status_code=400, detail="Invalid OTP")



@app.get("/auth/{provider}")
def login_social(provider: str):
    return {"auth_url": get_oauth_url(provider)}

@app.get("/auth/{provider}/callback")
def auth_callback(provider: str, code: str, db: Session = Depends(get_db)):
    user_info = get_user_info(provider, code)

    if not user_info or "email" not in user_info:
        raise HTTPException(status_code=400, detail="Invalid OAuth response")

    # Check if user exists
    existing_user = db.query(User).filter(User.email == user_info["email"]).first()
    if not existing_user:
        new_user = User(email=user_info["email"], username=user_info.get("name", "Unknown"))
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
    
    # Generate access token
    access_token = create_access_token({"sub": user_info["email"]})
    create_session(user_info["email"], access_token)
    
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/protected")
def protected_route(user: str = Depends(get_current_user)):
    return {"message": f"Hello, {user}! You have accessed a protected route."}