from unicodedata import name
from flask import Flask, render_template, url_for, request, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, LoginManager, UserMixin, logout_user, login_required
from datetime import datetime
import os

base_dir = os.path.dirname(os.path.realpath(__file__))

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"]='sqlite:///' + os.path.join(base_dir,'midas_blog.db')
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = '11eb39c9f684ba27b6bb287a642d4dddf5106e19'

db = SQLAlchemy(app)
login_manager = LoginManager(app)

# Initializing db

class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer(), primary_key=True)
    username = db.Column(db.String(25), nullable=False, unique=True)
    email = db.Column(db.String(50), nullable=False, unique=True)
    password_hash = db.Column(db.Text(25), nullable=False)
    
    def __repr__(self):
        return f"User <{self.username}>"


# Initializing Blog

class Blog(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    title = db.Column(db.String(75), nullable=False)
    content = db.Column(db.String(1000), nullable=False)
    author = db.Column(db.String(30), nullable=False)
    date = db.Column(db.DateTime, default=datetime.now())

    def __repr__(self):
        return f"Blog <{self.title}>"


# Initializing Contact Page Messages

class Message(db.Model):
    __tablename__ = "messages"
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(50), nullable=False)
    message = db.Column(db.String(), nullable=False)

    def __repr__(self):
        return f"Message <{self.name}>"


# Login Manager    

@login_manager.user_loader
def user_loader(id):
    return User.query.get(int(id))


# Index Route (Dashboard)

@app.route('/')
def dashboard():
    blogs = Blog.query.all()
    context = {
        "blogs": blogs
    }
    return render_template("dashboard.html", **context)


# Login Route

@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == 'POST':
        username = request.form.get("username")
        password = request.form.get("password")

        user = User.query.filter_by(username=username).first()
        # username doesn't exist or password incorrect.
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid credentials")
            return redirect(url_for('login'))
    return render_template("login.html")


# SignUp Route

@app.route('/signup', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")

        user_exists = User.query.filter_by(username=username, email=email).first()
        if user_exists:
            flash("User already exist!")
            return redirect(url_for("register"))

        password_hash = generate_password_hash(password)

        new_user = User(username=username, email=email, password_hash=password_hash)
        db.session.add(new_user)
        db.session.commit()
        
        return redirect(url_for("login"))
    
    return render_template("signup.html")


# Logout Route

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for("dashboard"))


# Contact Us Page

@app.route('/contact')
def contact():
    return render_template("contact.html")


# About Us Page

@app.route('/about')
def about():
    return render_template("about.html")




if __name__ == "__main__":
    app.run(debug=True)