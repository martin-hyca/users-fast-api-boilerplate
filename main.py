from fastapi import FastAPI, Request, Depends, Query
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from wtforms import Form as WTForm, StringField, PasswordField, validators
from sqlalchemy.orm import Session

from mydatabase import get_db
from models import User
from auth import verify_password, hash_password
from forms import RegistrationForm, LoginForm, ChangePasswordForm
from security import login_required, csrf_protect, get_current_user, generate_csrf_token
from flash import flash
from config import templates
from utilities import with_endpoint_name
# @csrf_protect


# Mock user data
# users = {"admin": "password123"}


# FastAPI app initialization
app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=generate_csrf_token) # used to be secret_key=secret_key

# mount static files
app.mount("/static/", StaticFiles(directory='static', html=True), name="static")


# Register GET
@app.get("/register", response_class=HTMLResponse)
@login_required
async def get_register(request: Request, user: str = Depends(get_current_user)):
    csrf_token = request.session.get('csrf_token')  # Get CSRF token from session
    form = RegistrationForm()
    return templates.TemplateResponse("register.html.j2", {"request": request, "form": form, "csrf_token": csrf_token, "user": user})

# Register POST
@app.post("/register")
@csrf_protect
async def register_user(request: Request, db: Session = Depends(get_db), user: str = Depends(get_current_user)):
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
async def settings(request: Request, user: str = Depends(get_current_user)):
    form = ChangePasswordForm()
    csrf_token = request.session.get('csrf_token')  # Get CSRF token from session
    return templates.TemplateResponse("settings.html.j2", {"request": request, "form": form, "csrf_token": csrf_token, "user": user})


# Change Password POST
@app.post("/settings")
@csrf_protect
async def change_password(request: Request, db: Session = Depends(get_db), user: str = Depends(get_current_user)):
    form_data = await request.form()
    form = ChangePasswordForm(formdata=form_data)

    if form.validate():
        # Fetch the current user from the database
        current_user = db.query(User).filter(User.username == user).first()
        if current_user and verify_password(form.current_password.data, current_user.hashed_password):
            # If the current password is correct, hash the new password and update it in the database
            new_hashed_password = hash_password(form.new_password.data)
            current_user.hashed_password = new_hashed_password
            db.commit()
            flash(request, "Password changed successfuly", "success")

            # Redirect to the success page or inform the user of successful password change
            return RedirectResponse(url="/success", status_code=302)
            # this is how I was passing the message before Flash: 
            # message = "Password changed successfuly"
            # return RedirectResponse(url=f"/success?message={message}", status_code=302)
        else:
            # Handle incorrect current password
            pass # Add logic to handle incorrect password

    # Handle validation errors or show form again
    return templates.TemplateResponse("settings.html.j2", {"request": request, "form": form, "user": user})


# Asking for login credentials
@app.get("/login", response_class=HTMLResponse)
@app.get("/", response_class=HTMLResponse)
@with_endpoint_name
async def login(request: Request, user: str = Depends(get_current_user)):
        # Generate CSRF token if it doesn't exist
    if 'csrf_token' not in request.session:
        csrf_token = generate_csrf_token()
        request.session['csrf_token'] = csrf_token
    else:
        csrf_token = request.session['csrf_token']

    form = LoginForm()
    message = request.session.pop('message', None)  # Retrieve and remove the message from the session
    return templates.TemplateResponse("index.html.j2", {"request": request, "form": form, "csrf_token": csrf_token, "user": user, "message": message, "endpoint_name": request.endpoint_name})

# Processing login
@app.post("/login")
@csrf_protect
@with_endpoint_name
async def login_post(request: Request, db: Session = Depends(get_db), user: str = Depends(get_current_user)):
    form_data = await request.form()
    form = LoginForm(formdata=form_data)
    csrf_token = generate_csrf_token()
    request.session['csrf_token'] = csrf_token

    if form.validate():
        username = form.username.data
        password = form.password.data
        user = db.query(User).filter(User.username == username).first()
        if user and verify_password(password, user.hashed_password):
            # Generate new CSRF token on successful login
            csrf_token = generate_csrf_token()
            request.session['csrf_token'] = csrf_token
            request.session['user'] = user.username
            user = request.session['user']
            flash(request, "Login successful", "success")
            # return templates.TemplateResponse("success.html.j2", {"request": request, "user": user})
            return RedirectResponse(url="/success", status_code=302)

    # If validation fails or login is incorrect, re-render the form with an error
    # Reuse the existing CSRF token for rendering the form again
    csrf_token = request.session.get('csrf_token', generate_csrf_token())
    message = "login incorrect"
    flash(request, "Login Incorrect", "danger")
    return templates.TemplateResponse("index.html.j2", {"request": request, "form": form, "csrf_token": csrf_token, "user": user, "message": message, "endpoint": request.endpoint_name})


# destination after successful login
@app.get("/success", response_class=HTMLResponse)
async def success(request: Request, user: str = Depends(get_current_user), message: str = Query(None)):
    if user:
        return templates.TemplateResponse("success.html.j2", {"request": request, "user": user, "message": message})
    return RedirectResponse(url="/", status_code=302)


@app.post("/logout")
async def logout(request: Request):
    request.session.pop('user', None)  # Remove 'user' from session
    return RedirectResponse(url="/", status_code=302)