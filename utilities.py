from typing import Callable
from starlette.requests import Request
from functools import wraps

def with_endpoint_name(endpoint: Callable):
    @wraps(endpoint)
    async def wrapper(*args, **kwargs):
        request = kwargs.get('request') or next((arg for arg in args if isinstance(arg, Request)), None)

        if request is None:
            # You might want to raise an exception or handle this case as per your application's need
            raise Exception("Request object not found")

        try:
            request.endpoint_name = request.scope["endpoint"].__name__
        except KeyError:
            # Log this error or handle it as per your application's need
            request.endpoint_name = None

        return await endpoint(*args, **kwargs)
    
    return wrapper