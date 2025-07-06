# File Manager Pro - Team Edition

A professional file management system designed for team collaboration with secure user authentication and comprehensive file operations.

## 🚀 Features

### 👥 **Team Management**
- **Pre-configured team accounts**: saad (Admin), husham (User), salah (User)
- **Role-based access control**: Admin and User roles with different permissions
- **Secure authentication**: Individual usernames and passwords for each team member
- **Activity tracking**: Every file operation is logged with the user who performed it

### 📁 **File Operations**
- **Multi-file upload**: Upload multiple files simultaneously with drag & drop support
- **Universal file support**: No restrictions on file types - upload anything
- **Advanced search**: Search files by name, description, and tags
- **Smart filtering**: Filter files by tags, file types, and upload date
- **Dual view modes**: Switch between grid and list views
- **File management**: Edit descriptions, add tags, replace files, and delete

### 🎨 **Modern Interface**
- **Dark theme design**: Professional dark interface with animated backgrounds
- **Responsive layout**: Works perfectly on desktop, tablet, and mobile devices
- **Smooth animations**: Engaging hover effects and transitions
- **Real-time updates**: Live file list updates and progress indicators
- **Intuitive UX**: User-friendly interface with clear navigation

### 🔧 **Technical Features**
- **RESTful API**: JSON endpoints for programmatic access
- **Database optimization**: Indexed search for fast file retrieval
- **Security**: Protection against SQL injection and secure file handling
- **CORS support**: Cross-origin requests for API integration
- **Backup system**: Create and manage team file backups

## 👥 Team Accounts

The system comes with three pre-configured accounts:

| Username | Role | Full Name | Password |
|----------|------|-----------|----------|
| `saad` | Admin | Saad (Admin) | `saad2024admin` |
| `husham` | User | Husham | `husham2024user` |
| `salah` | User | Salah | `salah2024user` |

### Admin Privileges
- Access to all team files
- User management capabilities
- System backup and restore
- Advanced file operations

### User Privileges
- Upload and manage own files
- View shared team files
- Basic file operations
- Search and filter capabilities

## 🛠 Installation & Setup

### Local Development

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd file_manager_team
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**
   ```bash
   python app.py
   ```

4. **Access the application**
   - Open your browser and go to `http://localhost:5000`
   - Use one of the team accounts to log in

### Railway Deployment

1. **Prepare for deployment**
   - Ensure all files are committed to Git
   - Push to GitHub repository

2. **Deploy to Railway**
   - Connect your GitHub repository to Railway
   - Railway will automatically detect the Python app
   - Environment variables will be set automatically

3. **Access your deployed app**
   - Railway will provide a public URL
   - Share this URL with your team members

## 📊 API Endpoints

### Authentication
- `POST /login` - User login
- `GET /logout` - User logout

### File Operations
- `GET /api/files` - List all files (JSON)
- `POST /upload` - Upload files
- `GET /download/<filename>` - Download file
- `POST /edit/<filename>` - Edit file metadata
- `POST /delete/<filename>` - Delete file

### System Operations
- `GET /backup` - Create system backup
- `POST /restore` - Restore from backup

## 🔒 Security Features

- **Password hashing**: Secure bcrypt password storage
- **Session management**: Flask-Login for secure sessions
- **CSRF protection**: WTForms CSRF tokens
- **File validation**: Secure file upload handling
- **SQL injection protection**: Parameterized queries

## 📱 Mobile Support

The application is fully responsive and works seamlessly on:
- Desktop computers (Windows, Mac, Linux)
- Tablets (iPad, Android tablets)
- Mobile phones (iOS, Android)
- All modern web browsers

## 🌍 Global Access

Once deployed on Railway, the application can be accessed from anywhere in the world:
- **24/7 availability**: Always online and accessible
- **Global CDN**: Fast loading from any location
- **HTTPS security**: Secure encrypted connections
- **Cross-platform**: Works on any device with a web browser

## 🔧 Customization

The system is designed to be easily customizable:

### Adding New Users
Edit the `TEAM_ACCOUNTS` dictionary in `app.py`:
```python
TEAM_ACCOUNTS = {
    'new_username': {
        'password': 'new_password',
        'full_name': 'New User Name',
        'role': 'user',  # or 'admin'
        'email': 'new_user@team.local'
    }
}
```

### Modifying UI Colors
Edit the CSS variables in `static/css/style.css`:
```css
:root {
    --primary-color: #your-color;
    --secondary-color: #your-color;
    --accent-color: #your-color;
}
```

### Adding File Type Restrictions
Modify the upload validation in `app.py` if needed (currently accepts all file types).

## 📈 Performance

- **Optimized database**: SQLite with proper indexing
- **Efficient file handling**: Streaming uploads and downloads
- **Minimal resource usage**: Lightweight Flask application
- **Fast search**: Indexed full-text search capabilities

## 🆘 Support

For technical support or questions:
1. Check the application logs for error details
2. Verify all team accounts are working correctly
3. Ensure proper file permissions in upload directories
4. Contact your system administrator for deployment issues

## 📄 License

This project is designed for team collaboration and internal use. Modify and distribute according to your team's needs.

---

**File Manager Pro Team Edition** - Professional file management for modern teams.

