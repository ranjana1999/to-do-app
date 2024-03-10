from flask import Flask, render_template, redirect, url_for, request, flash,session
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField,FileField
from google.cloud import secretmanager
from wtforms.validators import DataRequired, Length, Email
from wtforms.validators import EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import OperationalError
from werkzeug.utils import secure_filename 
import random
import os
import string
credential_path = "mysqlsa.json"
os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = credential_path
 
def generate_secret_key(length=32):
    characters = string.ascii_letters + string.digits
    secret_key = ''.join(random.choice(characters) for i in range(length))
    return secret_key
def access_secret_version(project_id, secret_id, version_id):
    client = secretmanager.SecretManagerServiceClient()

    # Build the resource name of the secret version.
    name = f"projects/{project_id}/secrets/{secret_id}/versions/{version_id}"

    # Access the secret version.
    response = client.access_secret_version(request={"name": name})
    # Print the secret payload.
    # snippet is showing how to access the secret material.
    payload = response.payload.data.decode("UTF-8")
    return payload
db_password = access_secret_version('fleet-purpose-411708','cloud_sql_passwd','1')

# Function call to show output    
#db_password = access_secret_version('fleet-purpose-411708', 'cloudsql_pwd','1')
app = Flask(__name__)
bcrypt = Bcrypt(app)
secret_key = generate_secret_key()
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', secret_key)
#app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:@localhost/User'
# configuration
app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"mysql+pymysql://root:{db_password}@"
    "34.118.7.206:3306/user"
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
 
login_manager = LoginManager(app)
login_manager.login_view = 'login'
 
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
 
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
 
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')
 
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=80)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Login')
 
class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='tasks')
    attachment = db.Column(db.String(255))
 
class TaskForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=255)])
    attachment = FileField('Attachment')
    submit = SubmitField('Add Task')
 
def check_database_connection():
    try:
        with app.app_context():
            # Attempt to connect to the database
            db.session.query(User).first()
        print("Database connection successful!")
    except OperationalError as e:
        print(f"Error connecting to the database: {e}")
 
@app.route('/')
def index():
    check_database_connection()
    return render_template("base.html")
 
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()    
    if request.method == 'POST':
        print(f'Form Data: {request.form}')
        if form.validate_on_submit():
            print('Form validation successful!')
            user = User(username=form.username.data, email=form.email.data, password=bcrypt.generate_password_hash(form.password.data).decode('utf-8'))
            db.session.add(user)
            db.session.commit()
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))
        else:
            print('Form validation failed. Errors:', form.errors)
    return render_template('register.html', form=form)
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
 
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        print(f'Form Data: {request.form}')  # Print form data
        print(f'User: {user}')  # Print user object
        stored_password_hash = user.password
        entered_password_hash = bcrypt.generate_password_hash(form.password.data)
        print(f'Stored Password Hash: {stored_password_hash}')
        print(f'Entered Password Hash: {entered_password_hash}')
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            print('Password match!')
            login_user(user)
            flash('Login successful', 'success')
            return redirect(url_for('add_task'))
        else:
            print('Password does not match!')
            flash('Invalid username or password', 'error')
    for field, errors in form.errors.items():
        for error in errors:
            flash(f'{field}: {error}', 'error')
    return render_template('login.html', form=form)
 
 
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))
 
@app.route('/welcome')
@login_required
def welcome():
    return render_template('welcome.html', current_user=current_user)
@app.route('/add_task', methods=['GET', 'POST'])
@login_required
def add_task():
    form = TaskForm()
 
    if form.validate_on_submit():
        task = Task(title=form.title.data, user=current_user)
        # Handle file upload
        print(type(form.attachment.data))
        if form.attachment.data:
            attachment_path = save_attachment(form.attachment.data)
            task.attachment = attachment_path
        db.session.add(task)
        db.session.commit()
        flash('Task added successfully!', 'success')
        return redirect(url_for('add_task'))
 
    return render_template('add_task.html', form=form)
def save_attachment(attachment):
    upload_folder = 'sqlitedemo/static/uploads'  # Replace 'your_flask_app' with your app name
    if not os.path.exists(upload_folder):
        os.makedirs(upload_folder)
    filename = secure_filename(attachment.filename)
    attachment_path = os.path.join(upload_folder, filename)
    print("Saving file to:", attachment_path)
    attachment.save(attachment_path)
    return attachment_path 
"""@app.route('/tasks')
@login_required
def view_tasks():
    # Fetch tasks for the current user from the database
    tasks = Task.query.filter_by(user=current_user).all()
    return render_template('view_tasks.html', tasks=tasks)"""
@app.route('/view_tasks')
@login_required
def view_tasks():
    tasks = Task.query.filter_by(user=current_user).all()
    return render_template('view_tasks.html', tasks=tasks)
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0',port=8080)