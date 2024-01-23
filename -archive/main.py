from fastapi import FastAPI, Request, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from starlette_wtf import CSRFProtectMiddleware, CSRFToken
from secrets import token_urlsafe
from wtforms import Form as WTForm, StringField, PasswordField, validators

# Mock user data
users = {
    "admin": "password123"
}

# CSRF and Secret tokens
csrf_secret = token_urlsafe(32)
secret_key = token_urlsafe(32)

# FastAPI app initialization
app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=secret_key)
app.add_middleware(CSRFProtectMiddleware, csrf_secret=csrf_secret)

# Jinja2 Templates
templates = Jinja2Templates(directory="templates")

# WTForm for login
class LoginForm(WTForm):
    username = StringField('Username', [validators.DataRequired()])
    password = PasswordField('Password', [validators.DataRequired()])

# Endpoint to display the login form
@app.get("/", response_class=HTMLResponse)
async def login(request: Request, csrf_token: CSRFToken = Depends(CSRFToken)):
    form = LoginForm()
    return templates.TemplateResponse("login.html", {"request": request, "form": form, "csrf_token": csrf_token})

# Endpoint for form submission
@app.post("/login")
async def login_post(request: Request, username: str = Form(...), password: str = Form(...)):
    form_data = await request.form()
    user = users.get(form_data.get('username'))
    if user and form_data.get('password') == user:
        response = RedirectResponse(url="/success", status_code=302)
        request.session['user'] = form_data.get('username')
        return response
    return RedirectResponse(url="/", status_code=302)

# Endpoint for successful login
@app.get("/success", response_class=HTMLResponse)
async def success(request: Request):
    user = request.session.get('user')
    if user:
        return templates.TemplateResponse("success.html", {"request": request, "user": user})
    return RedirectResponse(url="/", status_code=302)
