from fastapi import HTTPException
from authlib.integrations.requests_client import OAuth2Session

# Replace with your credentials from Google, Facebook, Apple, and LinkedIn
OAUTH_CONFIG = {
    "google": {
        "client_id": "YOUR_GOOGLE_CLIENT_ID",
        "client_secret": "YOUR_GOOGLE_CLIENT_SECRET",
        "authorize_url": "https://accounts.google.com/o/oauth2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "userinfo": "https://www.googleapis.com/oauth2/v2/userinfo"
    },
    "facebook": {
        "client_id": "YOUR_FACEBOOK_CLIENT_ID",
        "client_secret": "YOUR_FACEBOOK_CLIENT_SECRET",
        "authorize_url": "https://www.facebook.com/dialog/oauth",
        "token_url": "https://graph.facebook.com/oauth/access_token",
        "userinfo": "https://graph.facebook.com/me?fields=id,name,email"
    },
    "linkedin": {
        "client_id": "YOUR_LINKEDIN_CLIENT_ID",
        "client_secret": "YOUR_LINKEDIN_CLIENT_SECRET",
        "authorize_url": "https://www.linkedin.com/oauth/v2/authorization",
        "token_url": "https://www.linkedin.com/oauth/v2/accessToken",
        "userinfo": "https://api.linkedin.com/v2/me"
    },
    "apple": {
        "client_id": "YOUR_APPLE_CLIENT_ID",
        "client_secret": "YOUR_APPLE_CLIENT_SECRET",
        "authorize_url": "https://appleid.apple.com/auth/authorize",
        "token_url": "https://appleid.apple.com/auth/token"
    }
}

def get_oauth_url(provider: str):
    """Returns the OAuth URL for the provider"""
    if provider not in OAUTH_CONFIG:
        raise HTTPException(status_code=400, detail="Unsupported provider")

    config = OAUTH_CONFIG[provider]
    oauth = OAuth2Session(config["client_id"], config["client_secret"], scope="openid email profile")
    
    auth_url, _ = oauth.create_authorization_url(config["authorize_url"])
    return auth_url

def get_user_info(provider: str, code: str):
    """Fetch user info after OAuth login"""
    if provider not in OAUTH_CONFIG:
        raise HTTPException(status_code=400, detail="Unsupported provider")

    config = OAUTH_CONFIG[provider]
    oauth = OAuth2Session(config["client_id"], config["client_secret"])
    
    # Get access token
    token = oauth.fetch_token(config["token_url"], authorization_response=code)
    
    # Get user info
    user_info = oauth.get(config["userinfo"]).json()
    return user_info
