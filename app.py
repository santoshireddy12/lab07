from flask import Flask, render_template, request, redirect, url_for, session
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
import re

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
Session(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    first_name = db.Column(db.String(150), nullable=False)
    last_name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)


def init_db():
    db.create_all()

def check_password(password):
    errors = []
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long.")
    if not re.search(r'[a-z]', password):
        errors.append("Password must contain a lowercase letter.")
    if not re.search(r'[A-Z]', password):
        errors.append("Password must contain an uppercase letter.")
    if not re.search(r'\d$', password):
        errors.append("Password must end in a number.")
    return errors


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        session['username'] = username

        user = User.query.filter_by(username=username, password=password).first()
        if user:
            return redirect(url_for('secret'))
        else:
            return redirect(url_for('index', login_failed=True))
    return render_template('index.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            errors = ["Passwords do not match."]
            return render_template('signup.html', errors=errors)

        errors = check_password(password)
        if errors:
            return render_template('signup.html', errors=errors)

        if User.query.filter_by(email=email).first():
            errors = ["Email address already used."]
            return render_template('signup.html', errors=errors)

        new_user = User(username=username, first_name=first_name, last_name=last_name, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('thankyou'))
    return render_template('signup.html')


@app.route('/thankyou')
def thankyou():
    return render_template('thankyou.html')


@app.route('/secret')
def secret():
    if 'username' in session:
        return render_template('secret.html', username=session['username'])
    else:
        return redirect(url_for('index'))


if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(debug=True)
