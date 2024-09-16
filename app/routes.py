from flask import render_template, url_for, flash, redirect, request, Blueprint
from app import db, bcrypt
from app.models import User
from flask_login import login_user, logout_user, login_required
from app.forms import RegistrationForm


main = Blueprint('main', __name__)


@main.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # Проверка, если такие username или email уже есть
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            flash('This username is already taken. Please choose a different one.', 'danger')
            return redirect(url_for('main.register'))

        email = User.query.filter_by(email=form.email.data).first()
        if email:
            flash('This email is already registered. Please use a different one.', 'danger')
            return redirect(url_for('main.register'))

        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('main.login'))
    else:
        print(form.errors)
    return render_template('register.html', form=form)


@main.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('You have been logged in!', 'success')
            return redirect(url_for('main.profile'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html')


@main.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.login'))


@main.route('/profile')
@login_required
def profile():
    return render_template('profile.html')
