from flask import Flask, request, redirect, render_template, session, flash, url_for
from mysqlconnection import MySQLConnector
import re
import datetime
import time
import os, binascii
import md5
# salt = binascii.b2a_hex(os.urandom(15))

# Name Regular Expression
NAME_REGEX = re.compile(r'^[a-zA-Z]+$')

# Email Regular Expression
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

PW_REGEX = re.compile(r'^.*(?=.{8,})(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).*$')

app = Flask(__name__)

mysql = MySQLConnector(app,'users')

app.secret_key = 'LoginRegisterKey'

@app.route('/')

def index():
    if not 'method' in session:
        session['method']='register'

    return redirect('/'+session['method'])

@app.route('/results', methods=['POST'])
def results():

    valid = True
    confirm_pw = ''

    session['email'] = email = request.form['email']
    password = request.form['password']

    if session['method'] == 'register':
        if 'first_name' in request.form:
            session['first_name'] = first_name = request.form['first_name']
        if 'last_name' in request.form:
            session['last_name'] = last_name = request.form['last_name']
        if 'confirm_pw' in request.form:
            confirm_pw = request.form['confirm_pw']

        if len(first_name) < 1:
            flash("First name cannot be blank!", 'red')
            valid = False
        elif len(first_name) >= 1 and len(first_name) < 2:
            flash("First name must have 2 letters!", 'red')
            valid = False
        elif not NAME_REGEX.match(first_name):
            flash("Name can only contain letters!", 'red')
            valid = False
        else:
            flash("hidden", "hidden")

        if len(last_name) < 1:
            flash("Last name cannot be blank!", 'red ')
            valid = False
        elif len(last_name) >= 1 and len(last_name) < 2:
            flash("Last name must have 2 letters!", 'red')
            valid = False
        elif not NAME_REGEX.match(last_name):
            flash("Name can only contain letters!", 'red')
            valid = False
        else:
            flash("hidden", "hidden")

    if len(email) < 1:
        flash("Email cannot be blank!", 'red')
        valid = False
    elif not EMAIL_REGEX.match(email):
        flash("Invalid Email Address!", 'red')
        valid = False
    else:
        flash("hidden", "hidden")

    if len(password) < 1:
        flash("Password cannot be blank!", 'red ')
        valid = False
    elif len(password) < 8:
        flash("Password must be at least 8 characters!", 'red ')
        valid = False
    elif not PW_REGEX.match(password):
        flash("Password is weak!", 'red')
        flash("What is a strong password?", 'message')
        valid = False
    elif (confirm_pw) and (confirm_pw != password):
        flash("hidden", "hidden")
        flash("Password doesn't match!", 'red')
        valid = False
    else:
        flash("hidden", "hidden")
    
    if valid:
        # Determine if email already exists in DB
        verifyQuery = "SELECT count(id) as count, concat(first_name, ' ', last_name) as full_name, password as password_hash, salt FROM users where email = (:email)"
        data = {
                'email': email
            }
        exists = mysql.query_db(verifyQuery, data)

        # If email does not exist then add it to DB
        if(not int(exists[0]['count'])):
            if session['method'] == 'register':

                salt =  binascii.b2a_hex(os.urandom(15))
                hashed_pw = md5.new(password + salt).hexdigest()
                
                insertQuery = "INSERT INTO users (first_name, last_name, email, password, salt, created_at, updated_at) VALUES (:first_name, :last_name, :email, :hashed_pw, :salt, NOW(), NOW())"

                data = {
                        'first_name': first_name,
                        'last_name': last_name,
                        'email': email,
                        'hashed_pw': hashed_pw,
                        'salt': salt
                    }
                
                mysql.query_db(insertQuery, data)

                if 'first_name' in session:
                    session.pop('first_name')
                if 'last_name' in session:
                    session.pop('last_name')

                session.pop('email')
                session.pop('method')

                full_name = first_name + ' ' + last_name

                header = 'Registration Successful'
                return render_template('results.html', header = header, full_name = full_name, email = email)

            else:
                flash("User ({}) does not exist, please register or log in with valid email address!".format(email), 'red')
                return redirect('/register')
        else:
            if session['method'] == 'register':
                flash("User, ({}) already exist! Please log in or register with different email address!".format(email), 'red error')
                return redirect('/login')
            else:
                full_name = exists[0]['full_name']

                password_hash = exists[0]['password_hash']
                encrypted_password = md5.new(password + exists[0]['salt']).hexdigest()
                
                if password_hash == encrypted_password:
                    header = 'Login Successful'
                    return render_template('results.html', header = header, full_name = full_name, email = email)
                else:
                    flash("Error, password does not match password on file!.", 'red error no_match')
                    return redirect('/'+session['method'])
    else:
        return redirect('/'+session['method'])

@app.route('/login')
def login():
    session['method'] = 'login'
    header = 'Login'
    link = { 'href': "/register", 'text': 'Register' }
    displayItems = [ 'email', 'Email: ', 'password', 'Password: ' ]
    return render_template('index.html', header = header, link = link, display = displayItems)

@app.route('/register')
def register():
    session['method'] = 'register'
    header = 'Register'
    link = { 'href': "/login", 'text': 'Login' }
    displayItems = [ 'first_name', 'First Name: ', 'last_name', 'Last Name: ', 'email', 'Email: ', 'password', 'Password: ', 'confirm_pw', 'Confirm: ' ]
    return render_template('index.html', header = header, link = link, display = displayItems)

@app.route('/back', methods=['POST'])
def redirect_url():
    session['method'] = 'login'
    return redirect('/'+session['method'])

app.run(debug=True)