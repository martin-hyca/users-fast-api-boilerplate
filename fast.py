from fastapi import FastAPI, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from wtforms import Form as WTForm, StringField, PasswordField, validators
from secrets import token_urlsafe
from sqlalchemy.orm import Session

from mydatabase import get_db, Base, engine, SessionLocal
from models import User
from auth import verify_password, hash_password
from forms import RegistrationForm, LoginForm, ChangePasswordForm
from functools import wraps
from typing import Callable

from security import login_required, csrf_protect


# @csrf_protect


# Mock user data
# users = {"admin": "password123"}

# CSRF and Secret tokens
secret_key = token_urlsafe(32)

# FastAPI app initialization
app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=secret_key)

# Jinja2 Templates
templates = Jinja2Templates(directory="templates")

# CSRF token generation
def generate_csrf_token():
    return token_urlsafe(32)

# Register GET
@app.get("/register", response_class=HTMLResponse)
@login_required
async def get_register(request: Request):
    user = request.session.get('user')
    form = RegistrationForm()
    return templates.TemplateResponse("register.html.j2", {"request": request, "form": form, "user": user})

# Register POST
@app.post("/register")
async def register_user(request: Request, db: Session = Depends(get_db)):
    user = request.session.get('user')
    form_data = await request.form()
    form = RegistrationForm(formdata=form_data)
    if form.validate():
        hashed_password = hash_password(form.password.data)
        new_user = User(username=form.username.data, hashed_password=hashed_password)
        db.add(new_user)
        db.commit()
        return RedirectResponse(url="/success", status_code=302)
    return templates.TemplateResponse("register.html.j2", {"request": request, "form": form, "user": user})

# Change Password GET
@app.get("/settings", response_class=HTMLResponse)
@login_required
async def settings(request: Request):
    user = request.session.get('user')
    form = ChangePasswordForm()
    return templates.TemplateResponse("settings.html.j2", {"request": request, "form": form, "user": user})

# Change Password POST
@app.post("/settings")
async def change_password(request: Request, db: Session = Depends(get_db)):
    form_data = await request.form()
    form = ChangePasswordForm(formdata=form_data)
    user = request.session.get('user')

    if form.validate():
        # Fetch the current user from the database
        current_user = db.query(User).filter(User.user == user).first()
        if current_user and verify_password(form.current_password.data, current_user.hashed_password):
            # If the current password is correct, hash the new password and update it in the database
            new_hashed_password = hash_password(form.new_password.data)
            current_user.hashed_password = new_hashed_password
            db.commit()
            # Redirect to the success page or inform the user of successful password change
            return RedirectResponse(url="/success", status_code=302)
        else:
            # Handle incorrect current password
            pass # Add logic to handle incorrect password

    # Handle validation errors or show form again
    return templates.TemplateResponse("settings.html.j2", {"request": request, "form": form, "user": user})


# Asking for login credentials
@app.get("/login", response_class=HTMLResponse)
@app.get("/", response_class=HTMLResponse)
async def login(request: Request):
    user = request.session.get('user')
    csrf_token = generate_csrf_token()
    request.session['csrf_token'] = csrf_token
    form = LoginForm()
    message = request.session.pop('message', None)  # Retrieve and remove the message from the session
    return templates.TemplateResponse("login.html.j2", {"request": request, "form": form, "csrf_token": csrf_token, "user": user, "message": message})

# Processing login
@app.post("/login")
async def login_post(request: Request, db: Session = Depends(get_db)):
    user = request.session.get('user')
    form_data = await request.form()
    form = LoginForm(formdata=form_data)

    # Check CSRF token for security
    csrf_token = form_data.get('csrf_token')
    if not csrf_token or csrf_token != request.session.get('csrf_token'):
        raise HTTPException(status_code=400, detail="CSRF token mismatch")

    if form.validate():
        username = form.username.data
        password = form.password.data
        user = db.query(User).filter(User.username == username).first()
        if user and verify_password(password, user.hashed_password):
            response = RedirectResponse(url="/success", status_code=302)
            request.session['user'] = user.username
            return response

    # If validation fails or login is incorrect, re-render the form with an error
    return templates.TemplateResponse("login.html.j2", {"request": request, "form": form, "csrf_token": csrf_token, "user": user})


# destination after successful login
@app.get("/success", response_class=HTMLResponse)
async def success(request: Request):
    user = request.session.get('user')
    if user:
        return templates.TemplateResponse("success.html.j2", {"request": request, "user": user})
    return RedirectResponse(url="/", status_code=302)


@app.post("/logout")
async def logout(request: Request):
    request.session.pop('user', None)  # Remove 'user' from session
    return RedirectResponse(url="/", status_code=302)