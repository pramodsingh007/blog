
from flask import Flask, render_template, redirect, url_for, flash,get_flashed_messages,abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm,RegisterForm,LoginForm,CommentsForm
from flask_gravatar import Gravatar
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

#configuring login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

#loads the user object from user id store in the session
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


#making admin only decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args,**kwargs):
        #if id is not 1 then about
        if current_user.id !=1:
            return abort(403)
        return f(*args,**kwargs)

    return decorated_function



#creating table for user
class User(UserMixin,db.Model):
    id = db.Column(db.Integer,primary_key=True)
    name = db.Column(db.String,nullable=False)
    email = db.Column(db.String(50),nullable=False,unique=True)
    password = db.Column(db.String(100),nullable=False)
    posts = db.relationship('BlogPost',backref='owner')

    # comments = db.relationship('Comments',backref='author')
    
# db.create_all()


##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.String, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))


#creating table for comment
class Comments(db.Model):
    id = db.Column(db.Integer,primary_key = True)
    comment = db.Column(db.String(250))
    post_id = db.Column(db.Integer,nullable=False)
    author_name = db.Column(db.String(50),nullable =False)


db.create_all()

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts,logged_in=current_user.is_authenticated)


@app.route('/register',methods=["POST","GET"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data
        #check for if user is already registered if exit return True otherwise False
        if User.query.filter_by(email=email).first():
            flash(message="email already exist please login insted")
            return redirect(url_for('login'))
        else:
            hashed_password = generate_password_hash(password=password,method='pbkdf2:sha256',salt_length=6)

            new_user = User(name=name,email=email,password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('account created sucessfully!')
            return redirect(url_for('login'))


    return render_template("register.html",form=form)


@app.route('/login',methods=["POST","GET"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        #check for wrong email and password
        user = User.query.filter_by(email=form.email.data).first()
        try:
            if form.email.data != user.email or not check_password_hash(user.password,form.password.data):
                flash('Invalid email or password')
                return redirect(url_for('login'))
            else:
                #giving permission to the user to login
                login_user(user) 
                return redirect(url_for('get_all_posts',user=current_user.name))
        except:
            flash('Invalid email or password')
            return redirect(url_for('login'))
    return render_template("login.html",form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))

@app.route("/post/<int:post_id>",methods=["POST","GET"])
@login_required
def show_post(post_id):
    my_form = CommentsForm()
    requested_post = BlogPost.query.get(post_id)
    all_comment = Comments.query.filter_by(post_id= post_id)
    '''taking current user id and giving to the post route to check if current user id 
     is 1 or not so only admin can delete comments'''
    current_user_id = current_user.id
    
    #creating gravatar for user comments
    hashed_email = generate_password_hash(password= current_user.email,method='pbkdf2:sha256')
    avatar_link = f"https://www.gravatar.com/avatar/{hashed_email}"
    

    if my_form.validate_on_submit():
        comment = my_form.comment.data
        add_comment = Comments(comment=comment,post_id=post_id,author_name=current_user.name)
        db.session.add(add_comment)
        db.session.commit()
        return render_template("post.html", post=requested_post,logged_in=current_user.is_authenticated,form = my_form,comments=all_comment,current_user_id=current_user_id,avatar=avatar_link)
    return render_template("post.html", post=requested_post,logged_in=current_user.is_authenticated,form = my_form,comments=all_comment,current_user_id=current_user_id,avatar=avatar_link)


@app.route('/delete-comment/<int:comment_id>')
def delete_comment(comment_id):
    find_comment = Comments.query.get(comment_id)
    db.session.delete(find_comment)
    db.session.commit()
    return redirect(url_for('show_post',post_id=find_comment.post_id))



@app.route("/about")
def about():
    return render_template("about.html",logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html",logged_in=current_user.is_authenticated)


@app.route("/new-post",methods=['POST','GET'])
@login_required
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            author= current_user.name,
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            date=date.today().strftime("%B %d, %Y"),
            author_id = current_user.id
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form,logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body,
        
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        post.author_id = current_user.id
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form,logged_in=current_user.is_authenticated,is_edit=True)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
