from flask import Flask, render_template, url_for, request, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import current_user, login_user, LoginManager, UserMixin, logout_user, login_required
import datetime as dt
from datetime import date, datetime
import os
from forms import CreatePostForm, CommentForm
from flask_ckeditor import CKEditor
from sqlalchemy.orm import relationship
from flask_gravatar import Gravatar
from flask_bootstrap import Bootstrap

base_dir = os.path.dirname(os.path.realpath(__file__))

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"]="sqlite:///" + os.path.join(base_dir,"midas_blog.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
SECRET_KEY = os.urandom(32)
app.config["SECRET_KEY"] = SECRET_KEY
Bootstrap(app)
gravatar = Gravatar(app, size=100, rating="g", default="retro", force_default=False, force_lower=False, use_ssl=False, base_url=None)
ckeditor = CKEditor(app)

db = SQLAlchemy(app)
login_manager = LoginManager(app)


# Initializing db

class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer(), primary_key=True)
    username = db.Column(db.String(25), nullable=False, unique=True)
    email = db.Column(db.String(50), nullable=False, unique=True)
    password_hash = db.Column(db.Text(), nullable=False)
    blogs = relationship("Blog", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")
    joined_at = db.Column(db.DateTime(), default=datetime.utcnow, index=True)
    
    def __repr__(self):
        return f"User <{self.username}>"


# Initializing Blog

class Blog(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="blogs")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comment", back_populates="parent_post")

    def __repr__(self):
        return f"Blog <{self.title}>"
    
    
# Initializing Comment Page
class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    parent_post = relationship("Blog", back_populates="comments")
    comment_author = relationship("User", back_populates="comments")
    text = db.Column(db.Text, nullable=False)


# Initializing Contact Page Messages

class Message(db.Model):
    __tablename__ = "messages"
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(50), nullable=False)
    message = db.Column(db.String(), nullable=False)
    priority = db.Column(db.String(), nullable=False)

    def __repr__(self):
        return f"Message <{self.name}>"


# Login Manager    

@login_manager.user_loader
def user_loader(user_id):
    return User.query.get(int(user_id))


# Index Route (Dashboard)

@app.route("/")
def dashboard():
    blogs = Blog.query.all()
    user = current_user
    
    if user.is_authenticated:
        flash("Welcome back", "success")
    else:
        pass
    
    return render_template("dashboard.html", all_posts=blogs, user=user)


   
# Login Route

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = User.query.filter_by(username=username).first()
        # username doesn't exist or password incorrect.
        
        if not user:
            flash("That username does not exist, please try again.", "error")
            return redirect(url_for("login"))
        elif not check_password_hash(user.password_hash, password):
            flash("Password incorrect, please try again.", "error")
            return redirect(url_for("login"))
        else:
            login_user(user)
            return redirect(url_for("dashboard"))
        
    return render_template("login.html")


# SignUp Route

@app.route("/signup", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        password2 = request.form.get("confirm-password")
        terms = request.form.get("checkbox", type=bool)

        user_exists = User.query.filter_by(username=username).first()
        if user_exists:
            flash("Username taken, try another!", "error")
            return redirect(url_for("register"))
        
        email_exists = User.query.filter_by(email=email).first()
        if email_exists:
            flash("Email address already exist!", "error")
            return redirect(url_for("register"))
        
        # Checking password mismatch
        if password2 != password:
            flash("passwords don't match!", "error")
            return redirect(url_for("register"))
        
        # Password Length
        if len(password) < 7:
            flash("password must be greater than 6 characters!", "error")
            return redirect(url_for("register"))
        
        # Checking Terms 'n' Condition
        if terms != True:
            flash("Kindly read and accept the terms & conditions to proceed!", "error")
            return redirect(url_for("register"))
            
        password_hash = generate_password_hash(password)

        new_user = User(username=username, email=email, password_hash=password_hash)
        db.session.add(new_user)
        db.session.commit()
        
        flash("User created successfully, login below.", "success")
        
        return redirect(url_for("login"))
    
    return render_template("signup.html")


# Logout Route

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("dashboard"))


# Contact Us Page

@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        message = request.form.get("message")
        priority = request.form.get("priority")

        new_message = Message(name=name, email=email, message=message, priority=priority)
        db.session.add(new_message)
        db.session.commit()

        user = current_user
        if user:
            flash("Your message has been sent. We'll get back to you ASAP!", "success2")
        
        return redirect(url_for("contact"))
        
    return render_template("contact.html")

# About Us Page

@app.route("/about")
def about():
    return render_template("about.html")


# Route for POST

@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form = CommentForm()
    requested_post = Blog.query.get(post_id)
    user = current_user

    if form.validate_on_submit():
        if not user.is_authenticated:
            flash("You need to login or register to comment.", "error")
            return redirect(url_for("login"))

        new_comment = Comment(
            text=form.comment_text.data,
            comment_author=user,
            parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()

    return render_template("post.html", post=requested_post, form=form, user=user)


# Route for NEW POST

@app.route("/new-post", methods=["GET", "POST"])
@login_required
def add_new_post():
    form = CreatePostForm()
    user = current_user
    e = dt.datetime.now()
    if form.validate_on_submit():
        new_post = Blog(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=user,
            date=e.strftime("%B %d, %Y %I:%M%p")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("dashboard"))

    return render_template("make-post.html", form=form, user=user)


# Edit Post Route

@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@login_required
def edit_post(post_id):
    post = Blog.query.get(post_id)
    user = current_user
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=user,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, is_edit=True, user=user)


# Delete Route

@app.route("/delete/<int:post_id>")
@login_required
def delete_post(post_id):
    post_to_delete = Blog.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for("dashboard"))



if __name__ == "__main__":
    app.run(host="0.0.0.0", port="4000", debug=True)