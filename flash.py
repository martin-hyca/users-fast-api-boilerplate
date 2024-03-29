from fastapi import Request
import typing


def flash(request: Request, flashed_message: typing.Any, category: str = "primary") -> None:
   if "_messages" not in request.session:
      request.session["_messages"] = []
   request.session["_messages"].append({"message": flashed_message, "category": category})
    
def get_flashed_messages(request: Request):
   print(request.session)
   return request.session.pop("_messages") if "_messages" in request.session else []
