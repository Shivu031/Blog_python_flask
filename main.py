from flask import Flask, render_template, request, session, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
import json
from datetime import datetime
import math
import os
from werkzeug.utils import secure_filename
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity,set_access_cookies, unset_jwt_cookies
)
from flask import make_response
from werkzeug.security import generate_password_hash, check_password_hash

with open('config.json', 'r') as c:
    params = json.load(c)["params"]

local_server = True
app = Flask(__name__, static_folder='static')
app.config["JWT_SECRET_KEY"] = params['jwt-secret-key']  
jwt = JWTManager(app)
app.secret_key = 'super-secret-key'
app.config.update(
    MAIL_SERVER = 'smtp.gmail.com',
    MAIL_PORT = '465',
    MAIL_USE_SSL = True,
    MAIL_USERNAME = params['gmail-user'],
    MAIL_PASSWORD=  params['gmail-password'],
    JWT_TOKEN_LOCATION=["cookies"],
    JWT_COOKIE_SECURE=False,   # True only in HTTPS
    JWT_ACCESS_COOKIE_PATH="/",
    JWT_COOKIE_CSRF_PROTECT=False
)

@jwt.unauthorized_loader
def unauthorized_callback(reason):
    return redirect("/userlogin")

@jwt.invalid_token_loader
def invalid_token_callback(reason):
    return redirect("/userlogin")

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return redirect("/userlogin")

@jwt.needs_fresh_token_loader
def needs_fresh_token_callback(jwt_header, jwt_payload):
    return redirect("/userlogin")

@jwt.revoked_token_loader
def revoked_token_callback(jwt_header, jwt_payload):
    return redirect("/userlogin")

mail = Mail(app)
if(local_server):
    app.config['SQLALCHEMY_DATABASE_URI'] = params['local_uri']
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = params['prod_uri']

app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, params['upload_location'])
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
db = SQLAlchemy(app)

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

class Contacts(db.Model):
    sno = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    phone_num = db.Column(db.String(12), nullable=False)
    msg = db.Column(db.String(120), nullable=False)
    date = db.Column(db.DateTime, nullable=True)
    email = db.Column(db.String(20), nullable=False)

class Posts(db.Model):
    sno = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(80), nullable=False)
    slug = db.Column(db.String(21), nullable=False)
    content = db.Column(db.Text, nullable=False)
    tagline = db.Column(db.String(120), nullable=False)
    date = db.Column(db.DateTime, nullable=True)
    img_file = db.Column(db.String(12), nullable=True)

@app.route("/register", methods=['POST','GET'])
def register():
    if(request.method=='POST'):
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        if Users.query.filter_by(email=email).first():
            flash("Email already exists", "danger")
            return redirect('/register')
        
        hashed_pass = generate_password_hash(
            password,
            method="pbkdf2:sha256",
            salt_length=16
        )
        user = Users(username=username, email=email, password=hashed_pass)
        db.session.add(user)
        db.session.commit()
        return redirect('/userlogin')
    return render_template('register.html')

@app.route('/userlogin', methods=['POST','GET'])
def api_login():
    if request.method=='POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = Users.query.filter_by(email=email).first()
        if not user:
            flash("Email not found", "danger")
            return redirect('/userlogin')
        if not check_password_hash(user.password, password):
            flash("Incorrect entered password", "danger")
            return redirect('/userlogin')

        # Create JWT
        access_token = create_access_token(identity=str(user.id))

        # Store JWT in cookie
        response = make_response(redirect("/"))
        set_access_cookies(response, access_token)
        return response
    return render_template('userlogin.html')

@app.route("/userlogout")
def user_logout():
    response = make_response(redirect("/userlogin"))
    unset_jwt_cookies(response)
    return response

@app.route("/")
@jwt_required()
def home():
    user_id = get_jwt_identity()
    user = Users.query.get(user_id)
    posts = Posts.query.filter_by().all()
    last = math.ceil(len(posts)/int(params['no_of_posts']))
    page = request.args.get('page')
    if (not str(page).isnumeric()):
        page = 1
    page = int(page)
    posts = posts[(page-1)*int(params['no_of_posts']):(page-1)*int(params['no_of_posts'])+ int(params['no_of_posts'])]
    if page==1:
        prev = "#"
        next = "/?page="+ str(page+1)
    elif page==last:
        prev = "/?page="+ str(page-1)
        next = "#"
    else:
        prev = "/?page="+ str(page-1)
        next = "/?page="+ str(page+1)
    
    return render_template('index.html', params=params, posts=posts, prev=prev, next=next, user=user)


@app.route("/about")
@jwt_required()
def about():
    return render_template('about.html', params=params)

@app.route("/uploader" , methods=['GET', 'POST'])
def uploader():
    if "user" in session and session['user']==params['admin_user']:
        if request.method=='POST':
            f = request.files['file1']
            f.save(os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(f.filename)))
            return "Uploaded successfully!"
        
@app.route("/post/<string:post_slug>", methods=['GET'])
@jwt_required()
def post_route(post_slug):
    post = Posts.query.filter_by(slug=post_slug).first()
    return render_template('post.html', params=params, post=post)

@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "user" in session and session['user']==params['admin_user']:
        posts = Posts.query.all()
        return render_template("dashboard.html", params=params, posts=posts)

    if request.method=="POST":
        username = request.form.get("uname")
        userpass = request.form.get("upass")
        if username==params['admin_user'] and userpass==params['admin_password']:
            # set the session variable
            session['user']=username
            posts = Posts.query.all()
            return render_template("dashboard.html", params=params, posts=posts)
    else:
        return render_template("login.html", params=params)

@app.route("/edit/<string:sno>" , methods=['GET', 'POST'])
def edit(sno):
    if "user" in session and session['user']==params['admin_user']:
        if request.method=="POST":
            box_title = request.form.get('title')
            tline = request.form.get('tline')
            slug = request.form.get('slug')
            content = request.form.get('content')
            img_file = request.form.get('img_file')
            date = datetime.now()
        
            if sno=='0':
                post = Posts(title=box_title, slug=slug, content=content, tagline=tline, date=date, img_file=img_file)
                db.session.add(post)
                db.session.commit()
                return redirect("/dashboard")
            else:
                post = Posts.query.filter_by(sno=sno).first()
                post.title = box_title
                post.tagline = tline
                post.slug = slug
                post.content = content
                post.date = date
                post.img_file = img_file
                db.session.commit()
                return redirect('/edit/'+sno)

    post = Posts.query.filter_by(sno=sno).first()
    return render_template('edit.html', params=params, post=post, sno=sno)

@app.route("/delete/<string:sno>" , methods=['GET', 'POST'])
def delete(sno):
    if "user" in session and session['user']==params['admin_user']:
        post = Posts.query.filter_by(sno=sno).first()
        db.session.delete(post)
        db.session.commit()
    return redirect("/dashboard")

@app.route('/logout')
def logout():
    session.pop('user')
    return redirect('/dashboard')

@app.route("/contact", methods = ['GET', 'POST'])
@jwt_required()
def contact():
    if(request.method=='POST'):
        name = request.form.get('name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        message = request.form.get('message')
        entry = Contacts(name=name,email = email, phone_num = phone, msg = message, date= datetime.now() )
        db.session.add(entry)
        db.session.commit()
        mail.send_message('New message from ' + name,
            sender=email,
            recipients = [params['gmail-user']],
            body = message + "\n" + phone
        )
    return render_template('contact.html', params=params)


# app.run(debug=True)
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
