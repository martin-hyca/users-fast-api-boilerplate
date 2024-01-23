from starlette_wtf import StarletteForm
from wtforms import Form, StringField, PasswordField, validators
from wtforms.validators import DataRequired, Email, EqualTo
from wtforms.widgets import PasswordInput


class RegistrationForm(Form):
    username = StringField('Username', [validators.Length(min=4, max=25)])
    password = PasswordField('New Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Repeat Password')


class LoginForm(Form): 
    username = StringField('Username', [validators.DataRequired()])
    password = PasswordField('Password', [validators.DataRequired()])

class ChangePasswordForm(Form):
    current_password = PasswordField('Current Password', [validators.DataRequired()])
    new_password = PasswordField('New Password', [
        validators.DataRequired(),
        validators.Length(min=6, message="Password should be at least 6 characters long")
    ])
    confirm_password = PasswordField('Confirm New Password', [
        validators.EqualTo('new_password', message='Passwords must match')
    ])
    
        

class CreateAccountForm(StarletteForm):
    email = StringField(
        'Email address',
        validators=[
            DataRequired('Please enter your email address'),
            Email()
        ]
    )

    password = PasswordField(
        'Password',
        widget=PasswordInput(hide_value=False),
        validators=[
            DataRequired('Please enter your password'),
            EqualTo('password_confirm', message='Passwords must match')
        ]
    )

    password_confirm = PasswordField(
        'Confirm Password',
        widget=PasswordInput(hide_value=False),
        validators=[
            DataRequired('Please confirm your password')
        ]
    )