import os
from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth

load_dotenv()

app = FastAPI(title="OAuth2 Python Example")

# Session middleware to store state and mitigate CSRF
app.add_middleware(
    SessionMiddleware, 
    secret_key=os.getenv("SESSION_SECRET", "super-secret-key")
)

# Configure OAuth client
oauth = OAuth()
oauth.register(
    name="github",
    client_id=os.getenv("GITHUB_CLIENT_ID"),
    client_secret=os.getenv("GITHUB_CLIENT_SECRET"),
    access_token_url="https://github.com/login/oauth/access_token",
    authorize_url="https://github.com/login/oauth/authorize",
    api_base_url="https://api.github.com/",
    client_kwargs={"scope": "read:user user:email"},
)


@app.get("/")
def home():
    return {
        "message": "Welcome to OAuth2 Demo",
        "action": "Visit /login to authenticate with GitHub"
    }


@app.get("/login")
async def login(request: Request):
    redirect_uri = request.url_for("auth_callback")
    return await oauth.github.authorize_redirect(request, redirect_uri)


@app.get("/auth/callback")
async def auth_callback(request: Request):
    try:
        token = await oauth.github.authorize_access_token(request)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Authentication failed: {str(e)}")

    access_token = token.get("access_token")
    if not access_token:
        raise HTTPException(status_code=400, detail="Missing access token in response.")

    # Request profile data via Bearer token
    resp = await oauth.github.get("user", token=token)
    user_data = resp.json()

    request.session["user"] = {
        "id": user_data.get("id"),
        "login": user_data.get("login"),
        "name": user_data.get("name"),
    }

    return JSONResponse({
        "status": "Authenticated",
        "user": request.session["user"],
        "token_type": token.get("token_type"),
        "scope": token.get("scope")
    })


@app.get("/profile")
def profile(request: Request):
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return {"user": user}


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/")
