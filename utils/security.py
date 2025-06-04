from flask import session, redirect, url_for, flash
from functools import wraps

def role_required(allowed_roles):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if 'role' not in session:
                flash('Login required.', 'warning')
                return redirect(url_for('login'))
            if session['role'] not in allowed_roles:
                flash('Access denied.', 'danger')
                return redirect(url_for('home'))
            return f(*args, **kwargs)
        return wrapped
    return decorator