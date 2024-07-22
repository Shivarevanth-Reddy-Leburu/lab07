from app import app, db
from flask import render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import re
from app.models import User

@app.route('/')
def index():
    return redirect(url_for('sign_in'))

@app.route('/sign_in', methods=['GET', 'POST'])
def sign_in():
    if request.method == 'POST':
        nameOfTheUser = request.form['nameOfTheUser'].lower()
        passwordOfTheUser = request.form['password']
        user = User.query.filter_by(username=nameOfTheUser).first()
        
        if user is None:
            flash('Username entered is not correct', 'error')
        elif not check_password_hash(user.password, passwordOfTheUser):
            flash('Password entered is invalid', 'error')
        else:
            session['user_id'] = user.id
            return redirect(url_for('secret_page'))
    return render_template('sign_in.html')

@app.route('/sign_up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        nameOfTheUser = request.form['nameOfTheUser'].lower()
        createPassword = request.form['createPassword']
        verifyThePassword = request.form['verifyThePassword']

        # Validate passwords
        if createPassword != verifyThePassword:
            flash('The Password and confirm password is not the same! Please verify.', 'error')
            return redirect(url_for('sign_up'))
        
        if not re.match(r'^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}$', createPassword):
            flash('Password should have a minimum of 6 characters atleast and should be a combination of uppercase, lowercase and numbers', 'error')
            return redirect(url_for('sign_up'))

        # Check if username already exists
        if User.query.filter_by(username=nameOfTheUser).first():
            flash('This Username has been already registered', 'error')
            return redirect(url_for('sign_up'))

        # Check if email already exists
        if User.query.filter_by(email=email).first():
            flash('This Email id has been already registered', 'error')
            return redirect(url_for('sign_up'))

        # Hash the password using pbkdf2:sha256
        password_after_encryption = generate_password_hash(createPassword, method='pbkdf2:sha256')
        registered_user = User(first_name=first_name, last_name=last_name, email=email, username=nameOfTheUser, password=password_after_encryption)
        db.session.add(registered_user)
        db.session.commit()
        return redirect(url_for('thank_you'))

    return render_template('sign_up.html')

@app.route('/thankyou')
def thank_you():
    return render_template('thankyou.html')

@app.route('/secret')
def secret_page():
    if 'user_id' not in session:
        return redirect(url_for('sign_in'))
    return render_template('secretPage.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('sign_in'))
