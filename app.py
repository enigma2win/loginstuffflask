from flask import send_file, send_from_directory, request, jsonify, render_template, url_for, Flask, redirect, flash, Blueprint, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo
import openai
import pandas as pd
import numpy as np
from dotenv import load_dotenv
import os
import sqlite3




load_dotenv()
openai.api_key = os.getenv('OPENAI_API_KEY')
app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'thisisasecretkey'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)




login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80))
    paid = db.Column(db.Integer, nullable=True, default=0)
    files = db.Column(db.LargeBinary, nullable=True)


class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()], render_kw={"placeholder": "Email"})
    password = PasswordField('Password', validators=[DataRequired()], render_kw={"placeholder": "Password"})
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match')], render_kw={"placeholder": "Confirm Password"})
    accept_terms = BooleanField('I accept the Terms and Conditions', validators=[DataRequired()])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    remember = BooleanField('Remember Me')

    submit = SubmitField('Login')

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/")
@app.route("/index")
def index():
    
    return render_template("index.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('chat'))
    return render_template('login.html', form=form)


@app.route('/chat', methods=['GET', 'POST'])
@login_required
def chat():
    return render_template('chat.html')

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)



@app.route('/endpoint', methods=['GET', 'POST'])
@login_required
def endpoint():
    MODEL = "gpt-3.5-turbo"
    if request.method=='POST':
        data = request.json
        question = data['query']
        chat_history = [
            {"role": "system", "content": "Es um assistente bastante divertido que responde a qualquer pergunta que o usuario faz e tentas ser sempre o mais profissional possivel com um toque de divertido."}
        ]
        if question:
            chat_history.append({"role": "user", "content": question})
            response = openai.ChatCompletion.create(
            model=MODEL,
            messages=chat_history,
            temperature=0,
            )
            answer = response['choices'][0]['message']['content']
            chat_history.append({"role": "bot", "content": answer})
        else:
            answer = ''
    else:
        answer = ''
        chat_history = []
    return jsonify({'answer': answer, 'chat_history': chat_history})



if __name__ == "__main__":
    app.run(port=9000,debug=True)


