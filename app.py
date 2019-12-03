import os
from flask import Flask, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, IntegerField, SelectMultipleField
from wtforms.validators import InputRequired, Email, Length, EqualTo
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_table import Table, Col


basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'app.db')
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

######## ROUTES ########

######## INDEX ########

@app.route('/')
@app.route('/index')
@login_required
def index():
    if not student_profile_is_set():
        flash('Please set up your profile before continuing with the system!')
        return redirect(url_for('student_profile'))
    return render_template('index.html')

######## INDEX ########

######## SET UP PARAMS ########

@app.route('/set_up_parameters', methods=["GET", "POST"])
@login_required
def set_up_parameters():
    form = SetUpParametersForm()

    if form.validate_on_submit():
        if not form.max_size.data >= form.min_size.data:
            flash('Maximum team size must be greater than minimum team size.')
            return redirect(url_for('set_up_parameters'))
        try:
            t_param = TeamParameter.query.first()
            o = 'Updated existing parameter'
            if not t_param == None:
                t_param.min_size = form.min_size.data
                t_param.max_size = form.max_size.data
            else:
                o = 'New parameter has been created!'
                new_parameter = TeamParameter(max_size=form.max_size.data, min_size=form.min_size.data, active=True)
                db.session.add(new_parameter)
            db.session.commit()

            flash(o)
            return redirect(url_for('index'))
        except:
            flash('Something went wrong!')
        
    return render_template('set_up_parameters.html', form=form)

def is_team_creatable():
    return not (TeamParameter.query.first() == None)

######## SET UP PARAMS ########

######## CREATE TEAMS ########

@app.route('/create_teams', methods=["GET", "POST"])
@login_required
def create_teams():
    enabled = True
    form = CreateTeamForm()
    if not is_team_creatable():
        enabled = False
    if form.validate_on_submit():
        try:
            team = db.session.query(TeamsList.id).filter_by(team_name=form.team_name.data).scalar()
            if not team == None:
                flash('Team name already exists!')
                return redirect(url_for('create_teams'))
            else:
                o = 'Team created with \'{}\' as liason!'.format(current_user.username)
                add_one_to_team(team_name=form.team_name.data, username=current_user.username, liaison=True, new=True)
            db.session.commit()

            flash(o)
            return redirect(url_for('index'))
        except Exception as e:
            flash('Something went wrong! \n{}'.format(str(e)))

    return render_template('create_teams.html', enabled=enabled, form=form)

def add_one_to_team(team_name, username, liaison=False, new=False):
    scalar = db.session.query(TeamsList.id).filter_by(team_name=team_name).scalar()
    if (not (scalar == None)) or new:
        new_member = TeamsList(team_name=team_name, username=username, liaison=liaison)
        db.session.add(new_member)

def get_user_teams(username, liaison=False):
    scalar = db.session.query(TeamsList.id).filter_by(username=username).scalar()
    if not (scalar == None):
        _t = TeamsList.query.with_entities(TeamsList.team_name).filter_by(username=username).all()


######## CREATE TEAMS ########

######## STUDENT PROFILE ########

@app.route('/student_profile', methods=["GET", "POST"])
@login_required
def student_profile():
    form = StudentProfileForm()

    if form.validate_on_submit():
        try:
            student = db.session.query(Student.id).filter_by(username=current_user.username).scalar()
            o = 'Updated existing student'
            if not student == None:
                _s = Student.query.filter_by(username=current_user.username).first()
                _s.student_number = form.student_number.data
                _s.program = form.program.data
            else:
                o = 'New student profile has been created!'
                new_student = Student(username=current_user.username, student_number=form.student_number.data, program=form.program.data)
                db.session.add(new_student)
            db.session.commit()

            flash(o)
            return redirect(url_for('index'))
        except Exception as e:
            flash('Something went wrong! \n{}'.format(str(e)))
        
    return render_template('student_profile.html', form=form)

def student_profile_is_set():
    if current_user.instructor:
        return True
    else:
        return not (db.session.query(Student.id).filter_by(username=current_user.username).scalar() == None)

######## STUDENT PROFILE ########

@app.route('/accept_new_students')
@login_required
def accept_new_students():
    return 'Todo'

@app.route('/visualize_student_teams')
@login_required
def visualize_student_teams():
    return render_template('visualize_student_teams.html', data=db_get_all_teams())

@app.route('/view_teams')
@login_required
def view_teams():
    return render_template('view_my_teams.html', data= db_get_teams_for_user(current_user.username))

@app.route('/join_teams')
@login_required
def join_teams():
    return 'Todo'

######## ROUTES ########

######## DATABASE ########

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    instructor = db.Column(db.Boolean)

    def __repr__(self):
        return 'User {} Instructor {}'.format(self.username, str(bool(self.instructor)))

class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    student_number = db.Column(db.String(15))
    program = db.Column(db.String(80))

    def __repr__(self):
        return "<Student: {}>".format(self.student_number)

class TeamParameter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    max_size = db.Column(db.Integer)
    min_size = db.Column(db.Integer)
    active = db.Column(db.Boolean)

class TeamsList(db.Model):
    __tablename__ = "teams_list"
    id = db.Column(db.Integer, primary_key=True)
    team_name = db.Column(db.String(30), unique=True)
    username = db.Column(db.String(15))
    liaison = db.Column(db.Boolean)

    def __repr__(self):
        return "<Team Name: {}>".format(self.team_name)

def as_cursor(query):
    connection = db.engine.raw_connection()
    cursor = connection.cursor()
    cursor.execute(query)
    return cursor.fetchall()

def db_get_teams_for_user(username):
    return as_cursor('SELECT team_name FROM teams_list WHERE username is \'{}\''.format(username))

def db_pack_users_in_team(team_name):
    _dict = {
        'team_name' : team_name,
        'retrieved' : db_retrieve_users_in_team(team_name),
        'size' : db_count_members_in_team(team_name)
    }
    return _dict

def db_count_members_in_team(team_name):
    return as_cursor('SELECT COUNT(teams_list.username) FROM teams_list WHERE teams_list.team_name is \'{}\''.format(team_name))

def db_retrieve_users_in_team(team_name):
    return as_cursor('SELECT teams_list.username, student.student_number, student.program FROM teams_list INNER JOIN student ON teams_list.username=student.username WHERE teams_list.team_name is \'{}\''.format(team_name))

def db_get_team_names():
    return as_cursor('SELECT team_name FROM teams_list')

def db_get_all_teams():
    formattable = []
    for pair in db_get_team_names():
        t_name = pair[0]
        formattable.append(db_pack_users_in_team(t_name))
    return formattable
    

######## DATABASE ########

######## FORMS ########

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    submit = SubmitField('Sign In')

class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80), EqualTo('confirm', message='Passwords must match')])
    confirm = PasswordField('Confirm Password')
    instructor = BooleanField('Instructor')
    submit = SubmitField('Register')

class SetUpParametersForm(FlaskForm):
    min_size = IntegerField('Minimum Size')
    max_size = IntegerField('Maximum Size')
    submit = SubmitField('Set Up Parameters')

class StudentProfileForm(FlaskForm):
    student_number = StringField('Student Number', validators=[InputRequired(), Length(max=10)])
    program = StringField('Program', validators=[InputRequired(), Length(max=80)])
    submit = SubmitField('Update Profile')

class CreateTeamForm(FlaskForm):
    team_name = StringField('Team Name', validators=[InputRequired(), Length(max=30)])
    submit = SubmitField('Create Team')
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
        if not form.confirm.data == form.password.data:
            return redirect(url_for('signup'))
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
