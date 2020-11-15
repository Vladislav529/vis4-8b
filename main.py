from flask import Flask, render_template, abort, redirect, session, url_for, request, make_response, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.urls import url_parse
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo, Length
from hashlib import md5
from flask_moment import Moment
from flask_mail import Mail, Message
from time import time
import jwt
from threading import Thread

#<--------------------------------------------------------------------------------------------------> Основной код
#ДОБАВИТЬ МОБИЛЬНЫЕ ВЕРСИИ САЙТА
#ЗАМЕНЯТЬ КЛЮЧИ КАПЧИ ПРИ ВЫПУСКЕ САЙТА НА ХОСТИНГ
#СДЕЛАТЬ СБРОС ПАРОЛЯ ЧЕРЕЗ ЭЛЕКТРОННУЮ ПОЧТУ

app = Flask(__name__, template_folder = "html", static_folder = "css")

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'you-will-never-guess'
app.config['RECAPTCHA_PUBLIC_KEY'] = "6LcQwd8ZAAAAAP18pB5-iThualGk_FJsPMEG22Vh"
app.config['RECAPTCHA_PRIVATE_KEY'] = "6LcQwd8ZAAAAAMDS-5NQ_uZ6exUmuxU8cHIBRPa1"

app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'Vladislav.Osipov.023@gmail.com'
app.config['MAIL_DEFAULT_SENDER'] = 'Vladislav.Osipov.023@gmail.com'
app.config['MAIL_PASSWORD'] = '1590437286_Vlad_529' 

db = SQLAlchemy(app)
mail = Mail(app)
moment = Moment(app)
login = LoginManager(app)
login.login_view = 'login'

#<--------------------------------------------------------------------------------------------------> База данных
@login.user_loader
def load_user(id):
    return User.query.get(int(id))

followers = db.Table('followers',
    db.Column('follower_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('followed_id', db.Integer, db.ForeignKey('user.id'))
)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    posts = db.relationship('News', backref='author', lazy='dynamic')
    about_me = db.Column(db.String(140))
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    followed = db.relationship(
        'User', secondary=followers,
        primaryjoin=(followers.c.follower_id == id),
        secondaryjoin=(followers.c.followed_id == id),
        backref=db.backref('followers', lazy='dynamic'), lazy='dynamic')

    def __repr__(self):
        return '<User {}>'.format(self.username)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def follow(self, user):
        if not self.is_following(user):
            self.followed.append(user)

    def unfollow(self, user):
        if self.is_following(user):
            self.followed.remove(user)

    def is_following(self, user):
        return self.followed.filter(
            followers.c.followed_id == user.id).count() > 0

    def avatar(self, size):
        digest = md5(self.email.lower().encode('utf-8')).hexdigest()
        return 'https://www.gravatar.com/avatar/{}?d=identicon&s={}'.format(
            digest, size)

    def get_reset_password_token(self, expires_in=600):
        return jwt.encode(
            {'reset_password': self.id, 'exp': time() + expires_in},
            app.config['SECRET_KEY'], algorithm='HS256').decode('utf-8')

    @staticmethod
    def verify_reset_password_token(token):
        try:
            id = jwt.decode(token, app.config['SECRET_KEY'],
                            algorithms=['HS256'])['reset_password']
        except:
            return
        return User.query.get(id)

    # все свои посты и посты тех, на кого подписаны
    # def followed_posts(self):
    #     followed = Post.query.join(
    #         followers, (followers.c.followed_id == Post.user_id)).filter(
    #             followers.c.follower_id == self.id)
    #     own = Post.query.filter_by(user_id=self.id)
    #     return followed.union(own).order_by(Post.timestamp.desc()

@app.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.utcnow()
        db.session.commit()

class News(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String(100), nullable = True)
    text = db.Column(db.Text, nullable = False)
    date = db.Column(db.DateTime, default = datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self):
        return '<Post {}>'.format(self.body)

def send_email(subject, sender, recipients, text_body, html_body):
    msg = Message(subject, sender=sender, recipients=recipients)
    msg.body = text_body
    msg.html = html_body
    mail.send(msg)

def send_password_reset_email(user):
    token = user.get_reset_password_token()
    send_email('[vis4_8b] Сброс пароля',
               sender = 'Vladislav.Osipov.023@gmail.com',
               recipients=[user.email],
               text_body=render_template('reset_password_text.txt',
                                         user=user, token=token),
               html_body=render_template('reset_password_text.html',
                                         user=user, token=token))

#<--------------------------------------------------------------------------------------------------> Формы
class RegistrationForm(FlaskForm):
    username = StringField('Логин (имя)', validators=[DataRequired()])
    email = StringField('Email-адрес', validators=[DataRequired(), Email(message = "Введите корректный email-адрес! (например example@mail.ru)", granular_message = True)])
    password = PasswordField('Пароль', validators=[DataRequired()])
    password2 = PasswordField(
        'Повторите пароль', validators=[DataRequired(), EqualTo('password', message = 'Пароли должны совпадать!')])
    recaptcha = RecaptchaField()
    submit = SubmitField('Зарегистрироваться')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Это имя занято! Используйте другое.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('На такую электронную почту уже зарегистрирован аккаунт! Используйте другую.')

class LoginForm(FlaskForm):
    username = StringField('Логин (имя)', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    remember_me = BooleanField('Запомнить меня')
    recaptcha = RecaptchaField()
    submit = SubmitField('Войти')

class ResetPasswordForm(FlaskForm):
    email = StringField('Введите Email, зарегистрированный на ваш аккаунт', validators=[DataRequired(), Email()])
    submit = SubmitField('Сбросить пароль')

class GoResetPasswordForm(FlaskForm):
    password = PasswordField('Новый пароль', validators=[DataRequired()])
    password2 = PasswordField(
        'Повторите новый пароль', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Сменить пароль')

class EditProfileForm(FlaskForm):
    username = StringField('Имя', validators=[DataRequired()])
    about_me = TextAreaField('Обо мне', validators=[Length(min=0, max=140)])
    submit = SubmitField('Подтвердить')

    def __init__(self, original_username, *args, **kwargs):
        super(EditProfileForm, self).__init__(*args, **kwargs)
        self.original_username = original_username

    def validate_username(self, username):
        if username.data != self.original_username:
            user = User.query.filter_by(username=self.username.data).first()
            if user is not None:
                raise ValidationError('Это имя занято! Используйте другое.')

#<--------------------------------------------------------------------------------------------------> Обработка страниц
@app.route("/")
def index():
	#return render_template("index.html")
	all_news = News.query.order_by(News.date.desc()).limit(3).all()
	return render_template('index.html', all_news = all_news)

# @app.errorhandler(404)
# def not_found_error(error):
#     return render_template('404.html'), 404

@app.errorhandler(404)
def http_404_handler(error):
    return "<h1>Ошибка 404 - страница не найдена</h1>", 404

@app.route("/class")
def myclass():
    return render_template("myclass.html")

@app.route("/foto")
def foto():
    return render_template("foto.html")

@app.route("/lessons")
def lessons():
    return render_template("lessons.html")

@app.route("/gramoty")
def gramoty():
    return render_template("gramoty.html")

#<--------------------------------------------------------------------------------------------------> Пользователи
#@login_required - защита от невошедших пользователей
@app.route('/user/<username>')
@login_required
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    # posts = [
    #     {'author': user, 'body': 'Test post #1'},
    #     {'author': user, 'body': 'Test post #2'}
    # ]
    return render_template('user.html', user=user)

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm(current_user.username)
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.about_me = form.about_me.data
        db.session.commit()
        flash('Your changes have been saved.')
        #return redirect(url_for('edit_profile'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.about_me.data = current_user.about_me
    return render_template('edit_profile.html', form=form)

@app.route('/follow/<username>')
@login_required
def follow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('User {} not found.'.format(username))
        return redirect(url_for('index'))
    if user == current_user:
        flash('You cannot follow yourself!')
        return redirect(url_for('user', username=username))
    current_user.follow(user)
    db.session.commit()
    flash('You are following {}!'.format(username))
    return redirect(url_for('user', username=username))

@app.route('/unfollow/<username>')
@login_required
def unfollow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('User {} not found.'.format(username))
        return redirect(url_for('index'))
    if user == current_user:
        flash('You cannot unfollow yourself!')
        return redirect(url_for('user', username=username))
    current_user.unfollow(user)
    db.session.commit()
    flash('You are not following {}.'.format(username))
    return redirect(url_for('user', username=username))

#<--------------------------------------------------------------------------------------------------> Регистрация, вход и выход  
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username = form.username.data, email = form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('login'))
    return render_template('register.html', form = form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username = form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember = form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html', form = form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_password_reset_email(user)
        flash('Check your email for the instructions to reset your password')
        return redirect(url_for('login'))
    return render_template('reset_password.html', form = form)

@app.route('/go_reset_password?token=<token>', methods=['GET', 'POST'])
def go_reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    user = User.verify_reset_password_token(token)
    if not user:
        return redirect(url_for('index'))
    form = GoResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash('Your password has been reset.')
        return redirect(url_for('login'))
    return render_template('go_reset_password.html', form=form)

#<--------------------------------------------------------------------------------------------------> Админка
@app.route('/admin')
def admin_panel():
    return render_template("admin.html")

#<--------------------------------------------------------------------------------------------------> Новости для меня
@app.route('/vis4_8b')
def posts():
    my_news = News.query.order_by(News.date.desc()).all()
    return render_template("news_me.html", my_news = my_news)

@app.route('/new_post', methods = ['POST', 'GET'])
def create_article():
    if request.method == "POST":
        title = request.form['title']
        text = request.form['text']
        article = News(title = title, text = text)
        
        try:
            db.session.add(article)
            db.session.commit()
            return redirect('/vis4_8b')
        except:
            return "При добавлении статьи произошла ошибка"
    else:
        return render_template("new_post.html") 

@app.route('/delete_post/<int:id>')
def post_delete(id):
    article = News.query.get_or_404(id)
    try:
        db.session.delete(article)
        db.session.commit()
        return redirect('/vis4_8b')
    except:
        return "При удалении статьи произошла ошибка"

@app.route('/update_post/<int:id>', methods = ['POST', 'GET'])
def post_update(id):
    red_news = News.query.get(id)
    if request.method == "POST":
        red_news.title = request.form['title']
        red_news.text = request.form['text']
        
        try:
            db.session.commit()
            return redirect('/vis4_8b')
        except:
            return "При редактировании статьи произошла ошибка"
    else:
        return render_template("post_update.html", red_news = red_news) 

@app.route('/news/<int:id>')
def new_detail(id):
    this_new = News.News.query.get(id)
    return render_template("new_detail.html", this_new = this_new)

#<--------------------------------------------------------------------------------------------------> Старт проекта
if __name__ == "__main__":
	app.run(debug = True)