import os
import sqlite3
from datetime import datetime
from functools import wraps
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, jsonify, current_app, g
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
import bcrypt

# --- Configuration ---
DATABASE = 'file_manager.db'
UPLOAD_FOLDER = 'uploads'
BACKUP_FOLDER = 'backups'
SECRET_KEY = os.environ.get('SECRET_KEY', 'your_super_secret_key_here') # Use environment variable for production

# Pre-configured team accounts
TEAM_ACCOUNTS = {
    'saad': {
        'password': 'saad2024admin',
        'full_name': 'Saad (Admin)',
        'role': 'admin',
        'email': 'saad@team.local'
    },
    'husham': {
        'password': 'husham2024user',
        'full_name': 'Husham',
        'role': 'user',
        'email': 'husham@team.local'
    },
    'salah': {
        'password': 'salah2024user',
        'full_name': 'Salah',
        'role': 'user',
        'email': 'salah@team.local'
    }
}

# --- Flask App Setup ---
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['BACKUP_FOLDER'] = BACKUP_FOLDER
app.config['SECRET_KEY'] = SECRET_KEY
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max upload size

CORS(app) # Enable CORS for API access

# --- Login Manager Setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
login_manager.login_message = 'Please log in to access the file manager.'

# --- User Model ---
class User(UserMixin):
    def __init__(self, id, username, email, full_name, role, date_created, is_active=True):
        self.id = id
        self.username = username
        self.email = email
        self.full_name = full_name
        self.role = role
        self.date_created = date_created
        self._is_active = is_active

    @property
    def is_active(self):
        return self._is_active

    @staticmethod
    def get(user_id):
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        if user:
            return User(user['id'], user['username'], user['email'], 
                       user['full_name'], user['role'], user['date_created'], user['is_active'])
        return None

    @staticmethod
    def get_by_username(username):
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user:
            return User(user['id'], user['username'], user['email'], 
                       user['full_name'], user['role'], user['date_created'], user['is_active'])
        return None

    def check_password(self, password):
        db = get_db()
        user = db.execute('SELECT password_hash FROM users WHERE id = ?', (self.id,)).fetchone()
        if user:
            return bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8'))
        return False

    def is_admin(self):
        return self.role == 'admin'

@login_manager.user_loader
def load_user(user_id):
    return User.get(int(user_id))

# --- Database Functions ---
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    with app.open_resource('schema.sql', mode='r') as f:
        schema = f.read()
    db = get_db()
    db.executescript(schema)
    
    # Insert pre-configured team accounts if they don't exist
    for username, data in TEAM_ACCOUNTS.items():
        user = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
        if not user:
            hashed_password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            db.execute(
                'INSERT INTO users (username, email, password_hash, full_name, role, date_created) VALUES (?, ?, ?, ?, ?, ?)',
                (username, data['email'], hashed_password, data['full_name'], data['role'], datetime.now().isoformat())
            )
    db.commit()

    # Create upload and backup folders if they don't exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['BACKUP_FOLDER'], exist_ok=True)

# --- Forms ---
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign In')

class FileEditForm(FlaskForm):
    description = TextAreaField('Description', validators=[Length(max=500)])
    tags = StringField('Tags', validators=[Length(max=200)])
    submit = SubmitField('Save Changes')

# --- Decorators ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# --- Routes ---
@app.route('/')
@login_required
def index():
    db = get_db()
    files = db.execute('SELECT * FROM files ORDER BY upload_date DESC').fetchall()
    
    # Attach uploader_username to each file
    files_with_uploader = []
    for file in files:
        file_dict = dict(file) # Convert Row object to dictionary
        uploader = db.execute('SELECT username FROM users WHERE id = ?', (file_dict['user_id'],)).fetchone()
        file_dict['uploader_username'] = uploader['username'] if uploader else 'Unknown'
        files_with_uploader.append(file_dict)

    return render_template('index.html', files=files_with_uploader)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.get_by_username(form.username.data)
        if user and user.check_password(form.password.data):
            login_user(user)
            flash(f'Welcome back, {user.full_name} ({user.role.title()})!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            flash('Invalid username or password.', 'danger')
    
    # Pass team accounts to the login template for display
    team_accounts_display = {
        username: {
            'full_name': data['full_name'],
            'role': data['role']
        } for username, data in TEAM_ACCOUNTS.items()
    }
    return render_template('auth/login.html', form=form, team_accounts=team_accounts_display)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'files[]' not in request.files:
        flash('No file part', 'danger')
        return redirect(request.url)
    
    files = request.files.getlist('files[]')
    description = request.form.get('description', '')
    tags = request.form.get('tags', '')

    if not files or all(f.filename == '' for f in files):
        flash('No selected file', 'danger')
        return redirect(request.url)

    db = get_db()
    uploaded_count = 0

    for file in files:
        if file.filename == '':
            continue
        
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # Check if file already exists
        existing_file = db.execute('SELECT id FROM files WHERE filename = ?', (filename,)).fetchone()
        if existing_file:
            flash(f'File {filename} already exists. Please rename or delete the existing file.', 'warning')
            continue

        try:
            file.save(filepath)
            db.execute(
                'INSERT INTO files (filename, description, tags, upload_date, user_id) VALUES (?, ?, ?, ?, ?)',
                (filename, description, tags, datetime.now().isoformat(), current_user.id)
            )
            db.commit()
            uploaded_count += 1
        except Exception as e:
            flash(f'Error uploading {filename}: {str(e)}', 'danger')
            # Clean up partially uploaded file if any
            if os.path.exists(filepath):
                os.remove(filepath)
            db.rollback()

    if uploaded_count > 0:
        flash(f'Successfully uploaded {uploaded_count} file(s)!', 'success')
    else:
        flash('No files were uploaded.', 'info')

    return redirect(url_for('index'))

@app.route('/download/<filename>')
@login_required
def download_file(filename):
    db = get_db()
    file_record = db.execute('SELECT user_id FROM files WHERE filename = ?', (filename,)).fetchone()
    
    if file_record and (current_user.is_admin() or file_record['user_id'] == current_user.id):
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
    else:
        flash('You do not have permission to download this file.', 'danger')
        return redirect(url_for('index'))

@app.route('/edit/<filename>', methods=['GET', 'POST'])
@login_required
def edit_file(filename):
    db = get_db()
    file_record = db.execute('SELECT * FROM files WHERE filename = ?', (filename,)).fetchone()

    if not file_record:
        flash('File not found.', 'danger')
        return redirect(url_for('index'))
    
    # Check if user has permission to edit
    if not current_user.is_admin() and file_record['user_id'] != current_user.id:
        flash('You do not have permission to edit this file.', 'danger')
        return redirect(url_for('index'))

    form = FileEditForm()
    if form.validate_on_submit():
        description = form.description.data
        tags = form.tags.data
        
        db.execute(
            'UPDATE files SET description = ?, tags = ?, last_modified_by = ?, last_modified_date = ? WHERE filename = ?',
            (description, tags, current_user.id, datetime.now().isoformat(), filename)
        )
        db.commit()
        flash('File metadata updated successfully!', 'success')
        return redirect(url_for('index'))
    elif request.method == 'GET':
        form.description.data = file_record['description']
        form.tags.data = file_record['tags']
    
    return render_template('edit.html', form=form, filename=filename, file=file_record)

@app.route('/delete/<filename>', methods=['POST'])
@login_required
def delete_file(filename):
    db = get_db()
    file_record = db.execute('SELECT user_id FROM files WHERE filename = ?', (filename,)).fetchone()

    if not file_record:
        flash('File not found.', 'danger')
        return redirect(url_for('index'))
    
    # Check if user has permission to delete
    if not current_user.is_admin() and file_record['user_id'] != current_user.id:
        flash('You do not have permission to delete this file.', 'danger')
        return redirect(url_for('index'))

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(filepath):
        os.remove(filepath)
        db.execute('DELETE FROM files WHERE filename = ?', (filename,))
        db.commit()
        flash(f'File {filename} deleted successfully!', 'success')
    else:
        flash('File not found on disk.', 'warning')
    
    return redirect(url_for('index'))

@app.route('/create_backup')
@login_required
@admin_required
def create_backup():
    try:
        backup_filename = f'backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.zip'
        backup_filepath = os.path.join(app.config['BACKUP_FOLDER'], backup_filename)
        
        # Create a zip archive of the uploads folder and the database
        import zipfile
        with zipfile.ZipFile(backup_filepath, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # Add database file
            zipf.write(DATABASE, os.path.basename(DATABASE))
            
            # Add all files from the UPLOAD_FOLDER
            for root, _, files in os.walk(app.config['UPLOAD_FOLDER']):
                for file in files:
                    file_path = os.path.join(root, file)
                    zipf.write(file_path, os.path.relpath(file_path, app.config['UPLOAD_FOLDER']))
        
        flash(f'Backup created successfully: {backup_filename}', 'success')
        return send_from_directory(app.config['BACKUP_FOLDER'], backup_filename, as_attachment=True)
    except Exception as e:
        flash(f'Error creating backup: {str(e)}', 'danger')
        return redirect(url_for('index'))

@app.route('/restore_backup', methods=['POST'])
@login_required
@admin_required
def restore_backup():
    if 'backup_file' not in request.files:
        flash('No backup file provided.', 'danger')
        return redirect(url_for('index'))
    
    backup_file = request.files['backup_file']
    if backup_file.filename == '':
        flash('No selected backup file.', 'danger')
        return redirect(url_for('index'))
    
    if not backup_file.filename.endswith('.zip'):
        flash('Invalid backup file format. Only .zip files are allowed.', 'danger')
        return redirect(url_for('index'))

    try:
        # Save the uploaded backup file temporarily
        temp_backup_path = os.path.join(app.config['BACKUP_FOLDER'], secure_filename(backup_file.filename))
        backup_file.save(temp_backup_path)

        # Clear current uploads and database
        db = get_db()
        db.execute('DELETE FROM files')
        db.commit()
        for f in os.listdir(app.config['UPLOAD_FOLDER']):
            if f != '.gitkeep': # Don't delete .gitkeep
                os.remove(os.path.join(app.config['UPLOAD_FOLDER'], f))

        # Extract backup
        import zipfile
        with zipfile.ZipFile(temp_backup_path, 'r') as zipf:
            for member in zipf.namelist():
                if member == os.path.basename(DATABASE): # Restore database
                    with open(DATABASE, 'wb') as f_db:
                        f_db.write(zipf.read(member))
                elif member.startswith(app.config['UPLOAD_FOLDER'] + '/') or member.startswith('uploads/'): # Restore files
                    # Ensure target directory exists
                    target_path = os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(member))
                    with open(target_path, 'wb') as f_upload:
                        f_upload.write(zipf.read(member))
                elif not os.path.isdir(member): # Handle files directly in root of zip (e.g., if uploads was zipped directly)
                    target_path = os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(member))
                    if not os.path.exists(target_path): # Avoid overwriting if already handled by uploads/ path
                        with open(target_path, 'wb') as f_upload:
                            f_upload.write(zipf.read(member))

        # Re-initialize DB connection to pick up new database
        close_db()
        get_db()
        
        flash('Backup restored successfully!', 'success')
    except Exception as e:
        flash(f'Error restoring backup: {str(e)}', 'danger')
    finally:
        # Clean up temporary backup file
        if os.path.exists(temp_backup_path):
            os.remove(temp_backup_path)

    return redirect(url_for('index'))

# --- API Endpoints ---
@app.route('/api/files')
@login_required
def api_files():
    db = get_db()
    files = db.execute('SELECT * FROM files ORDER BY upload_date DESC').fetchall()
    
    files_data = []
    for file in files:
        file_dict = dict(file)
        uploader = db.execute('SELECT username FROM users WHERE id = ?', (file_dict['user_id'],)).fetchone()
        file_dict['uploader_username'] = uploader['username'] if uploader else 'Unknown'
        
        # Get last modifier username if available
        if file_dict['last_modified_by']:
            modifier = db.execute('SELECT username FROM users WHERE id = ?', (file_dict['last_modified_by'],)).fetchone()
            file_dict['last_modified_username'] = modifier['username'] if modifier else 'Unknown'
        else:
            file_dict['last_modified_username'] = None

        files_data.append(file_dict)

    return jsonify(files_data)

# --- Error Handlers ---
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

# --- Main Execution ---
if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(debug=True, port=5000)

