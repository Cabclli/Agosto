import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from flaskr.db import get_db
from flaskr.auth import login_required

bp = Blueprint('confi', __name__, url_prefix='/confi')

@bp.route('/configu', methods=('GET', 'POST'))
@login_required
def configu():
    if request.method == 'POST':
        pass
    return render_template('confi/configu.html')

