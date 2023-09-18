import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from flaskr.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')
@bp.route('/register', methods=('GET', 'POST'))

def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password2 = request.form['password2']
        email = request.form["email"]
        db = get_db()
        error = None

        if not username:
            error = 'usuario incorrecto.'

        elif "@" in username:
            error = 'el usuario no puede tener arroba'

        elif not email:
            error = "email incorrecto"

        elif "@" not in email:
            error = "el email debe tener arroba"  

        elif not password:
            error = 'contraseña  incorrecta.'

        elif password2 != password:
            error ="la contraseña no es la misma"

        if error is None:
            try:
                db.execute(
                    "INSERT INTO user (username, email, password) VALUES (?, ?, ?)",
                    (username,email,generate_password_hash(password)),
                )
                db.commit()
            except db.IntegrityError():
                error = f"usuario {username} o correo {email} ya esta en uso."
            else:
                return redirect(url_for("auth.login"))

        flash(error)

    return render_template('auth/register.html')

@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM user WHERE email = ? OR username = ?', (username,username)
        ).fetchone()

        if user is None:
            error = 'Incorrect username.'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('index'))

        flash(error)

    return render_template('auth/login.html')

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()
        

@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view


@bp.route('/configu', methods=('GET', 'POST'))
@login_required
def configu():
       
    
    if request.method == 'POST':
        email = request.form['email']
        error = None

        if not email:
            error = 'error email'
        if "@" not in email:
            error = 'error email: falta la arroba'

        if error is not None:
            flash(error)
        else:
            db = get_db()
            db.execute(
                'UPDATE user SET email = ? WHERE id = ?' ,
                (email, g.user['id'])
            )
            db.commit()
            return redirect(url_for('blog.index'))

    return render_template('confi/configu.html')