"""
Phishing Email Analyzer
------------------------
FastAPI app that lets an authenticated (AD/LDAP) user paste a raw email
and get back a parsed SPF/DKIM/DMARC summary, extracted URLs/attachments,
a risk score, and a plain-English "why this is suspicious" writeup.
"""

import os
from datetime import datetime, timedelta

from fastapi import FastAPI, Depends, HTTPException, Request, Form, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordBearer
import jwt

from app.auth_ldap import authenticate_user
from app.analyzer import analyze_raw_email
from app import db

# --- Config -------------------------------------------------------------

SECRET_KEY = os.environ.get("APP_SECRET_KEY", "change-me-in-env")
JWT_ALGO = "HS256"
JWT_EXPIRE_MINUTES = 60

app = FastAPI(title="Phishing Email Analyzer")
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login", auto_error=False)


@app.on_event("startup")
def on_startup():
    db.init_db()


# --- Helpers --------------------------------------------------------------

def create_token(username: str) -> str:
    payload = {
        "sub": username,
        "exp": datetime.utcnow() + timedelta(minutes=JWT_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGO)


def get_current_user(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGO])
        return payload.get("sub")
    except jwt.PyJWTError:
        return None


# --- Routes -----------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login")
    return templates.TemplateResponse(
        "index.html", {"request": request, "user": user}
    )


@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    ok, error = authenticate_user(username, password)
    if not ok:
        return templates.TemplateResponse(
            "login.html", {"request": request, "error": error or "Invalid credentials"}
        )
    token = create_token(username)
    response = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    response.set_cookie(key="access_token", value=token, httponly=True, max_age=JWT_EXPIRE_MINUTES * 60)
    return response


@app.get("/logout")
def logout():
    response = RedirectResponse(url="/login")
    response.delete_cookie("access_token")
    return response


@app.post("/analyze", response_class=HTMLResponse)
def analyze(request: Request, raw_email: str = Form(...)):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login")

    result = analyze_raw_email(raw_email)
    db.save_analysis(user, result)

    return templates.TemplateResponse(
        "result.html", {"request": request, "user": user, "result": result}
    )


@app.get("/history", response_class=HTMLResponse)
def history(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login")
    records = db.get_history(user)
    return templates.TemplateResponse(
        "history.html", {"request": request, "user": user, "records": records}
    )


@app.get("/health")
def health():
    """Used by the GitHub Actions deploy step / uptime checks."""
    return {"status": "ok"}
