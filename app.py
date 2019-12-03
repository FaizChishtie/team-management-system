import os
from flask import Flask, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user


basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'app.db')
bootstrap = Bootstrap(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

######## ROUTES ########

@app.route('/')
@app.route('/index')
@login_required
def index():
    return render_template('index.html')

@app.route('/set_up_parameters')
@login_required
def set_up_parameters():
    return render_template('set_up_parameters.html')

@app.route('/create_teams')
@login_required
def create_teams():
    return 'Todo'

@app.route('/accept_new_students')
@login_required
def accept_new_students():
    return 'Todo'

@app.route('/visualize_student_teams')
@login_required
def visualize_student_teams():
    return 'Todo'

@app.route('/view_teams')
@login_required
def view_teams():
    return 'Todo'

@app.route('/join_teams')
@login_required
def join_teams():
    return 'Todo'

######## ROUTES ########

######## DATABASE ########

db = SQLAlchemy(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    instructor = db.Column(db.Boolean)

    def __repr__(self):
        return 'User {} Instructor {}'.format(self.username, str(bool(self.instructor)))

######## DATABASE ########

######## FORMS ########

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    submit = SubmitField('Sign In')

class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    instructor = BooleanField('Instructor')
    submit = SubmitField('Register')

######## FORMS ########

######## LOGIN/SIGNUP ########

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('index'))

        flash('Invalid username or password')

    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        try: 
            new_user = User(username=form.username.data, email=form.email.data, password=hashed_password, instructor=form.instructor.data )
            db.session.add(new_user)
            db.session.commit()

            flash('New user \'{}\' has been created!'.format(form.username.data))
            flash('Please sign in {}!'.format(form.username.data))
            return redirect(url_for('login'))
        except:
            flash('Something went wrong! The email address you entered may already be in use!'.format(form.username.data))
        

    return render_template('signup.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

######## LOGIN/SIGNUP ########

if __name__ == "__main__":
    db.create_all()
    app.run(debug=True)
