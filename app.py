# File Manager Pro - Team Edition
# Custom version for Saad's team with predefined accounts

import os
import sqlite3
import shutil
import mimetypes
import bcrypt
from flask import Flask, render_template, request, redirect, url_for, send_from_directory, g, flash, abort, jsonify, session
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, FileField, SubmitField
from wtforms.validators import DataRequired, Length
from datetime import datetime
from werkzeug.utils import secure_filename
import zipfile
import json

# --- Configuration ---
DATABASE = 'file_manager.db'
UPLOAD_FOLDER = 'uploads'
BACKUP_FOLDER = 'backups'
MAX_CONTENT_LENGTH = 500 * 1024 * 1024  # 500MB max file size

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'team_file_manager_secret_key_2024')
app.config['WTF_CSRF_ENABLED'] = True

# Enable CORS for all routes
CORS(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access the file manager.'
login_manager.login_message_category = 'info'

# --- Predefined Team Accounts ---
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

# --- Forms ---
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign In')

# --- Database Functions ---
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    if not os.path.exists(DATABASE):
        with app.app_context():
            db = get_db()
            
            # Create tables
            db.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    full_name TEXT,
                    role TEXT DEFAULT 'user',
                    date_created TEXT NOT NULL,
                    is_active INTEGER DEFAULT 1
                )
            ''')
            
            db.execute('''
                CREATE TABLE IF NOT EXISTS files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    original_filename TEXT NOT NULL,
                    storage_filename TEXT NOT NULL UNIQUE,
                    description TEXT,
                    tags TEXT,
                    file_size INTEGER DEFAULT 0,
                    mime_type TEXT,
                    date_added TEXT NOT NULL,
                    date_modified TEXT,
                    modified_by_user_id INTEGER,
                    download_count INTEGER DEFAULT 0,
                    uploaded_by_username TEXT,
                    modified_by_username TEXT,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                    FOREIGN KEY (modified_by_user_id) REFERENCES users (id)
                )
            ''')
            
            # Create indexes
            db.execute('CREATE INDEX IF NOT EXISTS idx_files_user_id ON files(user_id)')
            db.execute('CREATE INDEX IF NOT EXISTS idx_files_date_added ON files(date_added)')
            db.execute('CREATE INDEX IF NOT EXISTS idx_files_tags ON files(tags)')
            db.execute('CREATE INDEX IF NOT EXISTS idx_files_filename ON files(original_filename)')
            db.execute('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)')
            
            # Insert predefined team accounts
            for username, account_info in TEAM_ACCOUNTS.items():
                password_hash = bcrypt.hashpw(account_info['password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                
                try:
                    db.execute(
                        '''INSERT INTO users (username, email, password_hash, full_name, role, date_created) 
                           VALUES (?, ?, ?, ?, ?, ?)''',
                        (username, account_info['email'], password_hash, account_info['full_name'], 
                         account_info['role'], datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                    )
                except sqlite3.IntegrityError:
                    # User already exists, skip
                    pass
            
            db.commit()
            print("Database initialized successfully with team accounts.")

# --- Helper Functions ---
def get_file_size(file_path):
    """Get file size in bytes"""
    try:
        return os.path.getsize(file_path)
    except OSError:
        return 0

def get_mime_type(filename):
    """Get MIME type of file"""
    mime_type, _ = mimetypes.guess_type(filename)
    return mime_type or 'application/octet-stream'

def format_file_size(size_bytes):
    """Format file size in human readable format"""
    if size_bytes == 0:
        return "0 B"
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while size_bytes >= 1024.0 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    return f"{size_bytes:.1f} {size_names[i]}"

def search_files(search_term, tag_filter=None):
    """Search files by filename, description, or tags (all users for team collaboration)"""
    db = get_db()
    query = """
        SELECT f.*, u.username as uploaded_by_username, 
               mu.username as modified_by_username
        FROM files f 
        LEFT JOIN users u ON f.user_id = u.id
        LEFT JOIN users mu ON f.modified_by_user_id = mu.id
        WHERE (f.original_filename LIKE ? OR f.description LIKE ? OR f.tags LIKE ?)
    """
    params = [f'%{search_term}%', f'%{search_term}%', f'%{search_term}%']
    
    if tag_filter and tag_filter != 'all':
        query += " AND f.tags LIKE ?"
        params.append(f'%{tag_filter}%')
    
    query += " ORDER BY f.date_added DESC"
    
    cursor = db.execute(query, params)
    return cursor.fetchall()

# --- Authentication Routes ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.get_by_username(form.username.data)
        if user and user.check_password(form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            flash(f'Welcome back, {user.full_name}!', 'success')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        flash('Invalid username or password', 'error')
    
    return render_template('auth/login.html', form=form, team_accounts=TEAM_ACCOUNTS)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))

# --- API Routes ---
@app.route('/api/files')
@login_required
def api_get_files():
    """API endpoint to get all files (team shared) with optional filtering"""
    try:
        search_term = request.args.get('search', '')
        tag_filter = request.args.get('tag', 'all')
        sort_by = request.args.get('sort', 'date_desc')
        
        db = get_db()
        
        if search_term:
            files = search_files(search_term, tag_filter)
        else:
            query = """
                SELECT f.*, u.username as uploaded_by_username, 
                       mu.username as modified_by_username
                FROM files f 
                LEFT JOIN users u ON f.user_id = u.id
                LEFT JOIN users mu ON f.modified_by_user_id = mu.id
                WHERE 1=1
            """
            params = []
            
            if tag_filter and tag_filter != 'all':
                query += " AND f.tags LIKE ?"
                params.append(f'%{tag_filter}%')
            
            # Apply sorting
            if sort_by == 'name_asc':
                query += " ORDER BY f.original_filename ASC"
            elif sort_by == 'name_desc':
                query += " ORDER BY f.original_filename DESC"
            elif sort_by == 'date_asc':
                query += " ORDER BY f.date_added ASC"
            else:  # date_desc (default)
                query += " ORDER BY f.date_added DESC"
            
            cursor = db.execute(query, params)
            files = cursor.fetchall()
        
        # Convert to list of dictionaries
        files_list = []
        for file in files:
            file_dict = dict(file)
            # Add formatted file size
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file['storage_filename'])
            if os.path.exists(file_path):
                file_dict['file_size_formatted'] = format_file_size(file['file_size'] or 0)
            else:
                file_dict['file_size_formatted'] = 'Unknown'
            files_list.append(file_dict)
        
        return jsonify(files_list)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats')
@login_required
def api_get_stats():
    """API endpoint to get file statistics for the team"""
    try:
        db = get_db()
        
        # Total files count
        total_files = db.execute('SELECT COUNT(*) as count FROM files').fetchone()['count']
        
        # Total storage used
        total_size = db.execute('SELECT SUM(file_size) as size FROM files').fetchone()['size'] or 0
        
        # Most popular files (by download count)
        popular_files = db.execute(
            '''SELECT f.original_filename, f.download_count, u.username as uploaded_by
               FROM files f 
               LEFT JOIN users u ON f.user_id = u.id
               ORDER BY f.download_count DESC LIMIT 5'''
        ).fetchall()
        
        # Files by type
        file_types = db.execute(
            'SELECT mime_type, COUNT(*) as count FROM files GROUP BY mime_type ORDER BY count DESC'
        ).fetchall()
        
        # Files by user
        files_by_user = db.execute(
            '''SELECT u.username, u.full_name, COUNT(f.id) as file_count
               FROM users u 
               LEFT JOIN files f ON u.id = f.user_id
               GROUP BY u.id, u.username, u.full_name
               ORDER BY file_count DESC'''
        ).fetchall()
        
        return jsonify({
            'total_files': total_files,
            'total_size': total_size,
            'total_size_formatted': format_file_size(total_size),
            'popular_files': [dict(f) for f in popular_files],
            'file_types': [dict(f) for f in file_types],
            'files_by_user': [dict(f) for f in files_by_user]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/tags')
@login_required
def api_get_tags():
    """API endpoint to get all unique tags"""
    try:
        db = get_db()
        cursor = db.execute('SELECT DISTINCT tags FROM files WHERE tags IS NOT NULL AND tags != ""')
        all_tags = set()
        
        for row in cursor:
            if row['tags']:
                tags = [tag.strip() for tag in row['tags'].split(',')]
                all_tags.update(tags)
        
        return jsonify(sorted(list(all_tags)))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# --- Main Routes ---
@app.route('/')
@login_required
def index():
    """Main page with file listing (team shared)"""
    db = get_db()
    search_term = request.args.get('search', '')
    tag_filter = request.args.get('tag', 'all')
    sort_by = request.args.get('sort', 'date_desc')
    
    if search_term:
        files = search_files(search_term, tag_filter)
    else:
        query = """
            SELECT f.*, u.username as uploaded_by_username, 
                   mu.username as modified_by_username
            FROM files f 
            LEFT JOIN users u ON f.user_id = u.id
            LEFT JOIN users mu ON f.modified_by_user_id = mu.id
            WHERE 1=1
        """
        params = []
        
        if tag_filter and tag_filter != 'all':
            query += " AND f.tags LIKE ?"
            params.append(f'%{tag_filter}%')
        
        # Apply sorting
        if sort_by == 'name_asc':
            query += " ORDER BY f.original_filename ASC"
        elif sort_by == 'name_desc':
            query += " ORDER BY f.original_filename DESC"
        elif sort_by == 'date_asc':
            query += " ORDER BY f.date_added ASC"
        else:  # date_desc (default)
            query += " ORDER BY f.date_added DESC"
        
        cursor = db.execute(query, params)
        files = cursor.fetchall()
    
    # Get all unique tags for the filter dropdown
    tags_cursor = db.execute('SELECT DISTINCT tags FROM files WHERE tags IS NOT NULL AND tags != ""')
    all_tags = set()
    for row in tags_cursor:
        if row['tags']:
            tags = [tag.strip() for tag in row['tags'].split(',')]
            all_tags.update(tags)
    
    return render_template('index.html', 
                         files=files, 
                         all_tags=sorted(list(all_tags)),
                         current_search=search_term,
                         current_tag=tag_filter,
                         current_sort=sort_by)

@app.route('/add', methods=['POST'])
@login_required
def add_file():
    """Add new file(s) to the system"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    files = request.files.getlist('file')
    description = request.form.get('description', '')
    tags = request.form.get('tags', '')
    
    if not files or all(f.filename == '' for f in files):
        return jsonify({'error': 'No files selected'}), 400
    
    uploaded_files = []
    db = get_db()
    
    try:
        for file in files:
            if file and file.filename != '':
                # Secure the filename
                original_filename = secure_filename(file.filename)
                
                # Create unique storage filename
                timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                storage_filename = f"{timestamp}_{original_filename}"
                
                # Save file
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], storage_filename)
                file.save(file_path)
                
                # Get file information
                file_size = get_file_size(file_path)
                mime_type = get_mime_type(original_filename)
                
                # Insert into database with tracking info
                db.execute(
                    '''INSERT INTO files 
                       (user_id, original_filename, storage_filename, description, tags, file_size, mime_type, 
                        date_added, uploaded_by_username) 
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (current_user.id, original_filename, storage_filename, description, tags, file_size, mime_type, 
                     datetime.now().strftime("%Y-%m-%d %H:%M:%S"), current_user.username)
                )
                
                uploaded_files.append({
                    'original_filename': original_filename,
                    'storage_filename': storage_filename,
                    'file_size': file_size,
                    'mime_type': mime_type,
                    'uploaded_by': current_user.username
                })
        
        db.commit()
        
        if request.headers.get('Content-Type') == 'application/json' or request.is_json:
            return jsonify({
                'message': f'{len(uploaded_files)} file(s) uploaded successfully by {current_user.username}',
                'files': uploaded_files
            })
        else:
            flash(f'{len(uploaded_files)} file(s) uploaded successfully!', 'success')
            return redirect(url_for('index'))
            
    except Exception as e:
        db.rollback()
        if request.headers.get('Content-Type') == 'application/json' or request.is_json:
            return jsonify({'error': str(e)}), 500
        else:
            flash(f'Upload failed: {str(e)}', 'error')
            return redirect(url_for('index'))

@app.route('/edit/<int:file_id>', methods=['GET', 'POST'])
@login_required
def edit_file(file_id):
    """Edit file metadata (any team member can edit any file)"""
    db = get_db()
    file_record = db.execute('SELECT * FROM files WHERE id = ?', (file_id,)).fetchone()
    
    if not file_record:
        abort(404)
    
    if request.method == 'POST':
        description = request.form.get('description', '')
        tags = request.form.get('tags', '')
        new_file = request.files.get('file')
        
        storage_filename = file_record['storage_filename']
        original_filename = file_record['original_filename']
        file_size = file_record['file_size']
        mime_type = file_record['mime_type']
        
        # If a new file is uploaded, replace the old one
        if new_file and new_file.filename != '':
            # Delete old file
            old_file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_record['storage_filename'])
            if os.path.exists(old_file_path):
                os.remove(old_file_path)
            
            # Save new file
            original_filename = secure_filename(new_file.filename)
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            storage_filename = f"{timestamp}_{original_filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], storage_filename)
            new_file.save(file_path)
            
            # Update file information
            file_size = get_file_size(file_path)
            mime_type = get_mime_type(original_filename)
        
        # Update database with modification tracking
        db.execute(
            '''UPDATE files 
               SET description = ?, tags = ?, original_filename = ?, storage_filename = ?, 
                   file_size = ?, mime_type = ?, date_modified = ?, modified_by_user_id = ?,
                   modified_by_username = ?
               WHERE id = ?''',
            (description, tags, original_filename, storage_filename, file_size, mime_type,
             datetime.now().strftime("%Y-%m-%d %H:%M:%S"), current_user.id, current_user.username, file_id)
        )
        db.commit()
        
        flash(f'File updated successfully by {current_user.username}!', 'success')
        return redirect(url_for('index'))
    
    return render_template('edit.html', file=file_record)

@app.route('/delete/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    """Delete a file (any team member can delete any file)"""
    db = get_db()
    file_record = db.execute('SELECT storage_filename, original_filename FROM files WHERE id = ?', (file_id,)).fetchone()
    
    if file_record:
        # Delete the physical file
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_record['storage_filename'])
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
        except OSError as e:
            print(f"Error deleting file {file_path}: {e}")
        
        # Delete the record from the database
        db.execute('DELETE FROM files WHERE id = ?', (file_id,))
        db.commit()
        
        if request.headers.get('Content-Type') == 'application/json' or request.is_json:
            return jsonify({'message': f'File "{file_record["original_filename"]}" deleted successfully by {current_user.username}'})
        else:
            flash(f'File deleted successfully by {current_user.username}!', 'success')
    
    return redirect(url_for('index'))

@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    """Download a file (any team member can download any file)"""
    db = get_db()
    file_record = db.execute('SELECT * FROM files WHERE id = ?', (file_id,)).fetchone()
    
    if not file_record:
        abort(404)
    
    # Increment download count
    db.execute('UPDATE files SET download_count = download_count + 1 WHERE id = ?', (file_id,))
    db.commit()
    
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_record['storage_filename'])
    if not os.path.exists(file_path):
        abort(404)
    
    return send_from_directory(
        app.config['UPLOAD_FOLDER'], 
        file_record['storage_filename'], 
        as_attachment=True, 
        download_name=file_record['original_filename']
    )

@app.route('/backup')
@login_required
def create_backup():
    """Create a backup of all team files and data (admin only)"""
    if not current_user.is_admin():
        flash('Only admin can create backups.', 'error')
        return redirect(url_for('index'))
    
    if not os.path.exists(BACKUP_FOLDER):
        os.makedirs(BACKUP_FOLDER)
    
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    backup_filename = f'team_backup_{timestamp}'
    backup_path = os.path.join(BACKUP_FOLDER, f'{backup_filename}.zip')
    
    try:
        db = get_db()
        all_files = db.execute('SELECT storage_filename FROM files').fetchall()
        
        with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # Add all files
            for file_record in all_files:
                file_path = os.path.join(UPLOAD_FOLDER, file_record['storage_filename'])
                if os.path.exists(file_path):
                    zipf.write(file_path, f"files/{file_record['storage_filename']}")
            
            # Add team data as JSON
            team_data = {
                'users': [dict(u) for u in db.execute('SELECT * FROM users').fetchall()],
                'files': [dict(f) for f in db.execute('SELECT * FROM files').fetchall()]
            }
            zipf.writestr('team_data.json', json.dumps(team_data, indent=2))
            
            # Add metadata
            metadata = {
                'backup_date': datetime.now().isoformat(),
                'created_by': current_user.username,
                'total_files': len(all_files),
                'version': '2.0-team'
            }
            zipf.writestr('backup_metadata.json', json.dumps(metadata, indent=2))
        
        return send_from_directory(BACKUP_FOLDER, f'{backup_filename}.zip', as_attachment=True)
        
    except Exception as e:
        flash(f'Backup failed: {str(e)}', 'error')
        return redirect(url_for('index'))

# --- Error Handlers ---
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(413)
def too_large_error(error):
    flash('File too large. Maximum size is 500MB.', 'error')
    return redirect(url_for('index'))

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

# --- Main Execution ---
if __name__ == '__main__':
    # Ensure necessary folders exist
    for folder in [UPLOAD_FOLDER, BACKUP_FOLDER]:
        if not os.path.exists(folder):
            os.makedirs(folder)
    
    # Initialize database
    init_db()
    
    # Run the application
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

