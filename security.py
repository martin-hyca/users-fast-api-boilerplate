from functools import wraps
from fastapi import Request, HTTPException
from fastapi.responses import RedirectResponse
from typing import Callable, Optional
from config import templates
from secrets import token_urlsafe


from flash import flash




# CSRF and Secret tokens
# secret_key = token_urlsafe(32)

# CSRF token generation
def generate_csrf_token():
    return token_urlsafe(32)


async def get_current_user(request: Request) -> Optional[str]:
    return request.session.get('user')


# async def get_current_user(request: Request) -> str:
#     user = request.session.get('user')
#     if not user:
#       return RedirectResponse(url="/", status_code=302)
#     return user

def csrf_protect(endpoint: Callable):
    @wraps(endpoint)
    async def wrapper(*args, **kwargs):
        request = kwargs.get('request') or next((arg for arg in args if isinstance(arg, Request)), None)

        if request is None:
            raise HTTPException(status_code=500, detail="Request object not found")

        form_data = await request.form()
        csrf_token = form_data.get('csrf_token')
        session_csrf_token = request.session.get('csrf_token')

        if not csrf_token or csrf_token != session_csrf_token:
            # Redirect to a specific page or render a template with an error message
            flash(request, 'Error: CSRF token mismatch. Please, <a href="/" class="alert-link">proceed to the main page.</a>', "danger")
            return templates.TemplateResponse("index.html.j2", {"request": request}) # before Flash, the dict used to contain: , "message": "CSRF token mismatch"

            # raise HTTPException(status_code=400, detail="CSRF token mismatch")

        return await endpoint(*args, **kwargs)

    return wrapper


def login_required(endpoint: Callable):
    @wraps(endpoint)
    async def wrapper(*args, **kwargs):
        # Find the request object in args or kwargs
        request = kwargs.get('request') or next((arg for arg in args if isinstance(arg, Request)), None)
        
        if request is None:
            raise HTTPException(status_code=500, detail="Request object not found")

        user = request.session.get('user')
        if not user:
            flash(request, 'Error: You need to login first.', "danger")
            return RedirectResponse(url="/login", status_code=302)

        return await endpoint(*args, **kwargs)

    return wrapper

