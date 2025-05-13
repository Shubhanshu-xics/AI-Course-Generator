from fastapi import FastAPI, Depends, HTTPException  # Import FastAPI components for building API endpoints
from sqlalchemy.orm import Session  # Import session handling from SQLAlchemy
from database import SessionLocal, engine, Base  # Import database configuration
from models import User  # Import the User model
from schemas import UserCreate, UserResponse, UserLogin  # Import schemas for data validation
from security import hash_password, verify_password, create_access_token, get_current_user  # Import security functions
from session_manager import create_session, get_session, delete_session  # Import session management functions
from mfa import generate_otp, verify_otp  # Import Multi-Factor Authentication (MFA) functions
from social_auth import get_oauth_url, get_user_info  # Import social authentication functions
from slowapi import Limiter  # Import request rate limiter
from slowapi.util import get_remote_address  # Utility function to get client IP address
from starlette.requests import Request  # Import request handling from Starlette

# Initialize FastAPI application
app = FastAPI()

# Create database tables based on defined models
Base.metadata.create_all(bind=engine)

# Initialize rate limiter to prevent brute force attacks
limiter = Limiter(key_func=get_remote_address)

# Dependency to get a new database session for each request
def get_db():
    db = SessionLocal()  # Create a new database session
    try:
        yield db  # Yield session for use in request
    finally:
        db.close()  # Close session after request

# User Registration Endpoint
@app.post("/register", response_model=UserResponse)
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    # Check if the email is already registered
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Hash the user's password before saving to the database
    hashed_password = hash_password(user.password)
    
    # Create new user record
    new_user = User(email=user.email, username=user.username, password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return new_user  # Return the newly created user data

# User Login Endpoint
@app.post("/login")
@limiter.limit("5/minute")  # Apply rate limiting (5 requests per minute)
def login_user(request: Request, user: UserLogin, db: Session = Depends(get_db)):
    # Retrieve user from database
    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user or not verify_password(user.password, db_user.password):
        raise HTTPException(status_code=400, detail="Invalid email or password")
    
    # Generate an access token for authentication
    access_token = create_access_token({"sub": db_user.email})
    create_session(db_user.email, access_token)  # Store session for user
    
    return {"access_token": access_token, "token_type": "bearer"}

# User Logout Endpoint
@app.post("/logout")
def logout_user(user: str = Depends(get_current_user)):
    delete_session(user)  # Remove user session
    return {"message": "Logged out successfully"}

# Check Active Session Endpoint
@app.get("/session")
def get_user_session(user: str = Depends(get_current_user)):
    session = get_session(user)  # Retrieve session details
    if not session:
        raise HTTPException(status_code=401, detail="Session expired or not found")
    
    return {"message": "Session is active", "token": session}

# Generate MFA OTP (One-Time Password)
@app.post("/mfa/generate")
def generate_mfa_otp(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user:
        raise HTTPException(status_code=400, detail="User not found")
    
    otp = generate_otp(db_user.email)  # Generate an OTP for MFA
    
    return {"message": "OTP sent", "otp": otp}  # In real apps, send via email/SMS

# Verify MFA OTP
@app.post("/mfa/verify")
def verify_mfa_otp(email: str, otp: str):
    if verify_otp(email, otp):
        return {"message": "MFA verification successful"}
    raise HTTPException(status_code=400, detail="Invalid OTP")

# Social Login - Get OAuth URL
@app.get("/auth/{provider}")
def login_social(provider: str):
    return {"auth_url": get_oauth_url(provider)}  # Return OAuth URL for provider

# Social Login Callback
@app.get("/auth/{provider}/callback")
def auth_callback(provider: str, code: str, db: Session = Depends(get_db)):
    user_info = get_user_info(provider, code)  # Retrieve user info from provider
    
    if not user_info or "email" not in user_info:
        raise HTTPException(status_code=400, detail="Invalid OAuth response")
    
    # Check if user already exists in the database
    existing_user = db.query(User).filter(User.email == user_info["email"]).first()
    if not existing_user:
        # Create new user if not found
        new_user = User(email=user_info["email"], username=user_info.get("name", "Unknown"))
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
    
    # Generate an access token
    access_token = create_access_token({"sub": user_info["email"]})
    create_session(user_info["email"], access_token)  # Store session
    
    return {"access_token": access_token, "token_type": "bearer"}

# Protected Route Example
@app.get("/protected")
def protected_route(user: str = Depends(get_current_user)):
    return {"message": f"Hello, {user}! You have accessed a protected route."}
