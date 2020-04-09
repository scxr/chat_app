from flask import Flask, render_template, request, redirect, session
from flask_socketio import SocketIO, send
from flask_sqlalchemy import SQLAlchemy
import os, bcrypt


app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(16)
app.config['SQLALCHEMY_DATABASE_URI'] = r'sqlite:///C:\Users\cswil\OneDrive\Old stuff\Desktop\programming\web_dev_portfolio\chat_app\main.db'
socketio = SocketIO(app)
db = SQLAlchemy(app)


global salt
salt = b'$2b$12$dhqXNig3Gky4P2m4rmcor.'

class chat_history(db.Model):
    id = db.Column('id', db.Integer,primary_key=True)
    msg = db.Column('msg', db.String(500))

class login(db.Model):
    id = db.Column('id', db.Integer, primary_key=True)
    uname = db.Column('uname', db.String)
    password = db.Column('password', db.String)

@app.route('/register')
def load_registerpage():
    return render_template('register.html')

@app.route('/register_func', methods=['POST'])
def register_user():
    print(request.data)
    uname = request.form.get('username')
    password = request.form['password']
    password = bcrypt.hashpw(password.encode('utf-8'), salt)
    user = login(uname=uname, password=password)
    db.session.add(user)
    db.session.commit()
    return render_template('index.html')

@app.route('/login', methods=['GET'])
def load_loginpage():
    if 'logged_in' in session and session['logged_in'] == True:
        return "Already logged in! please visit /logout to logout"
    return render_template('login.html')

@app.route('/login_func', methods=['POST'])
def login_user():
    uname = request.form.get('username')
    given_pwd = request.form.get('password')
    password = bcrypt.hashpw(given_pwd.encode('utf-8'), salt)
    real_pass = login.query.filter_by(uname=uname).first()
    if real_pass.password == password:
        global username
        username = uname
        session['logged_in'] = True
        return redirect('/')
    else:
        return 'incorrect password'

@socketio.on('message')
def process_message(msg):
    message = chat_history(msg=msg)
    db.session.add(message)
    db.session.commit()
    if msg == 'User connected':
        msg = username + ' has connected'
    else:
        msg = username + ' said: ' + msg
    send(msg, broadcast=True)
    print('msg : '+msg)

@app.route('/logout')
def logout():
    session['logged_in'] = False
    return redirect('login')

@app.route('/')
def index():
    if 'logged_in' not in session or session['logged_in'] != True:
        session['logged_in'] = False
        return redirect('/login')    
    else:
        messages = chat_history.query.all()
        return render_template('index.html', msgs=messages)

        
if __name__ == "__main__":
    socketio.run(app, debug=True)