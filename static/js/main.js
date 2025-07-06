// File Manager Pro - Advanced JavaScript Functionality

class FileManagerPro {
    constructor() {
        this.selectedFiles = [];
        this.currentView = 'grid';
        this.currentSort = 'date_desc';
        this.currentFilter = 'all';
        this.searchTerm = '';
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.setupDragAndDrop();
        this.loadFiles();
        this.setupSearch();
        this.setupViewToggle();
        this.setupSorting();
        this.setupFiltering();
    }

    setupEventListeners() {
        // File input change
        const fileInput = document.getElementById('fileInput');
        if (fileInput) {
            fileInput.addEventListener('change', (e) => this.handleFileSelect(e));
        }

        // Upload form submit
        const uploadForm = document.getElementById('uploadForm');
        if (uploadForm) {
            uploadForm.addEventListener('submit', (e) => this.handleUpload(e));
        }

        // Search input
        const searchInput = document.getElementById('searchInput');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => this.handleSearch(e));
        }

        // Sort select
        const sortSelect = document.getElementById('sortSelect');
        if (sortSelect) {
            sortSelect.addEventListener('change', (e) => this.handleSort(e));
        }

        // Filter select
        const filterSelect = document.getElementById('filterSelect');
        if (filterSelect) {
            filterSelect.addEventListener('change', (e) => this.handleFilter(e));
        }

        // View toggle buttons
        const gridViewBtn = document.getElementById('gridView');
        const listViewBtn = document.getElementById('listView');
        if (gridViewBtn) gridViewBtn.addEventListener('click', () => this.setView('grid'));
        if (listViewBtn) listViewBtn.addEventListener('click', () => this.setView('list'));

        // Backup button
        const backupBtn = document.getElementById('backupBtn');
        if (backupBtn) {
            backupBtn.addEventListener('click', () => this.createBackup());
        }
    }

    setupDragAndDrop() {
        const dropZone = document.getElementById('dropZone');
        if (!dropZone) return;

        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, this.preventDefaults, false);
            document.body.addEventListener(eventName, this.preventDefaults, false);
        });

        ['dragenter', 'dragover'].forEach(eventName => {
            dropZone.addEventListener(eventName, () => this.highlight(dropZone), false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, () => this.unhighlight(dropZone), false);
        });

        dropZone.addEventListener('drop', (e) => this.handleDrop(e), false);
    }

    preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    highlight(element) {
        element.classList.add('dragover');
    }

    unhighlight(element) {
        element.classList.remove('dragover');
    }

    handleDrop(e) {
        const dt = e.dataTransfer;
        const files = dt.files;
        this.handleFiles(files);
    }

    handleFileSelect(e) {
        const files = e.target.files;
        this.handleFiles(files);
    }

    handleFiles(files) {
        this.selectedFiles = Array.from(files);
        this.displaySelectedFiles();
        this.updateUploadButton();
    }

    displaySelectedFiles() {
        const container = document.getElementById('selectedFiles');
        if (!container) return;

        if (this.selectedFiles.length === 0) {
            container.style.display = 'none';
            return;
        }

        container.style.display = 'block';
        const filesList = container.querySelector('.files-list');
        filesList.innerHTML = '';

        this.selectedFiles.forEach((file, index) => {
            const fileItem = document.createElement('div');
            fileItem.className = 'file-item';
            fileItem.innerHTML = `
                <div class="file-info">
                    <svg class="file-icon" viewBox="0 0 24 24" fill="currentColor">
                        <path d="M14,2H6A2,2 0 0,0 4,4V20A2,2 0 0,0 6,22H18A2,2 0 0,0 20,20V8L14,2M18,20H6V4H13V9H18V20Z"/>
                    </svg>
                    <div>
                        <div class="file-name">${file.name}</div>
                        <div class="file-size">${this.formatFileSize(file.size)}</div>
                    </div>
                </div>
                <button type="button" class="remove-file" onclick="fileManager.removeFile(${index})">
                    <svg viewBox="0 0 24 24" fill="currentColor" width="12" height="12">
                        <path d="M19,6.41L17.59,5L12,10.59L6.41,5L5,6.41L10.59,12L5,17.59L6.41,19L12,13.41L17.59,19L19,17.59L13.41,12L19,6.41Z"/>
                    </svg>
                </button>
            `;
            filesList.appendChild(fileItem);
        });
    }

    removeFile(index) {
        this.selectedFiles.splice(index, 1);
        this.displaySelectedFiles();
        this.updateUploadButton();
    }

    updateUploadButton() {
        const uploadBtn = document.getElementById('uploadBtn');
        if (!uploadBtn) return;

        if (this.selectedFiles.length > 0) {
            uploadBtn.disabled = false;
            uploadBtn.textContent = `Upload ${this.selectedFiles.length} File${this.selectedFiles.length > 1 ? 's' : ''}`;
        } else {
            uploadBtn.disabled = true;
            uploadBtn.textContent = 'Select Files to Upload';
        }
    }

    async handleUpload(e) {
        e.preventDefault();
        
        if (this.selectedFiles.length === 0) {
            this.showNotification('Please select files to upload', 'warning');
            return;
        }

        const description = document.getElementById('description').value;
        const tags = document.getElementById('tags').value;
        const uploadBtn = document.getElementById('uploadBtn');
        
        uploadBtn.disabled = true;
        uploadBtn.innerHTML = '<span class="loading"></span> Uploading...';

        try {
            for (let i = 0; i < this.selectedFiles.length; i++) {
                const file = this.selectedFiles[i];
                await this.uploadSingleFile(file, description, tags);
                
                // Update progress
                const progress = ((i + 1) / this.selectedFiles.length) * 100;
                this.updateProgress(progress);
            }

            this.showNotification('Files uploaded successfully!', 'success');
            this.resetUploadForm();
            this.loadFiles();
        } catch (error) {
            this.showNotification('Upload failed: ' + error.message, 'error');
        } finally {
            uploadBtn.disabled = false;
            uploadBtn.textContent = 'Upload Files';
            this.hideProgress();
        }
    }

    async uploadSingleFile(file, description, tags) {
        const formData = new FormData();
        formData.append('file', file);
        formData.append('description', description || `Uploaded file: ${file.name}`);
        formData.append('tags', tags);

        const response = await fetch('/add', {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
    }

    updateProgress(percentage) {
        const progressBar = document.querySelector('.progress-fill');
        const progressContainer = document.querySelector('.progress-bar');
        
        if (progressContainer) {
            progressContainer.style.display = 'block';
        }
        
        if (progressBar) {
            progressBar.style.width = percentage + '%';
        }
    }

    hideProgress() {
        const progressContainer = document.querySelector('.progress-bar');
        if (progressContainer) {
            progressContainer.style.display = 'none';
        }
    }

    resetUploadForm() {
        const form = document.getElementById('uploadForm');
        if (form) {
            form.reset();
        }
        
        this.selectedFiles = [];
        this.displaySelectedFiles();
        this.updateUploadButton();
    }

    setupSearch() {
        let searchTimeout;
        const searchInput = document.getElementById('searchInput');
        
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                clearTimeout(searchTimeout);
                searchTimeout = setTimeout(() => {
                    this.searchTerm = e.target.value.toLowerCase();
                    this.filterAndDisplayFiles();
                }, 300);
            });
        }
    }

    setupViewToggle() {
        const gridViewBtn = document.getElementById('gridView');
        const listViewBtn = document.getElementById('listView');
        
        if (gridViewBtn && listViewBtn) {
            gridViewBtn.addEventListener('click', () => this.setView('grid'));
            listViewBtn.addEventListener('click', () => this.setView('list'));
        }
    }

    setView(view) {
        this.currentView = view;
        
        const gridViewBtn = document.getElementById('gridView');
        const listViewBtn = document.getElementById('listView');
        const filesGrid = document.querySelector('.files-grid');
        const filesList = document.querySelector('.files-list');
        
        if (view === 'grid') {
            gridViewBtn?.classList.add('active');
            listViewBtn?.classList.remove('active');
            filesGrid?.classList.add('active');
            filesList?.classList.remove('active');
        } else {
            listViewBtn?.classList.add('active');
            gridViewBtn?.classList.remove('active');
            filesList?.classList.add('active');
            filesGrid?.classList.remove('active');
        }
    }

    setupSorting() {
        const sortSelect = document.getElementById('sortSelect');
        if (sortSelect) {
            sortSelect.addEventListener('change', (e) => {
                this.currentSort = e.target.value;
                this.filterAndDisplayFiles();
            });
        }
    }

    setupFiltering() {
        const filterSelect = document.getElementById('filterSelect');
        if (filterSelect) {
            filterSelect.addEventListener('change', (e) => {
                this.currentFilter = e.target.value;
                this.filterAndDisplayFiles();
            });
        }
    }

    async loadFiles() {
        try {
            const response = await fetch('/api/files');
            if (response.ok) {
                this.files = await response.json();
                this.filterAndDisplayFiles();
                this.updateFilesCount();
            }
        } catch (error) {
            console.error('Error loading files:', error);
            // Fallback to page reload if API is not available
            window.location.reload();
        }
    }

    filterAndDisplayFiles() {
        if (!this.files) return;

        let filteredFiles = [...this.files];

        // Apply search filter
        if (this.searchTerm) {
            filteredFiles = filteredFiles.filter(file => 
                file.original_filename.toLowerCase().includes(this.searchTerm) ||
                file.description.toLowerCase().includes(this.searchTerm) ||
                (file.tags && file.tags.toLowerCase().includes(this.searchTerm))
            );
        }

        // Apply tag filter
        if (this.currentFilter !== 'all') {
            filteredFiles = filteredFiles.filter(file => 
                file.tags && file.tags.toLowerCase().includes(this.currentFilter.toLowerCase())
            );
        }

        // Apply sorting
        filteredFiles.sort((a, b) => {
            switch (this.currentSort) {
                case 'name_asc':
                    return a.original_filename.localeCompare(b.original_filename);
                case 'name_desc':
                    return b.original_filename.localeCompare(a.original_filename);
                case 'date_asc':
                    return new Date(a.date_added) - new Date(b.date_added);
                case 'date_desc':
                default:
                    return new Date(b.date_added) - new Date(a.date_added);
            }
        });

        this.displayFiles(filteredFiles);
    }

    displayFiles(files) {
        const filesGrid = document.querySelector('.files-grid');
        const filesList = document.querySelector('.files-list');
        
        if (filesGrid) {
            filesGrid.innerHTML = '';
            files.forEach(file => {
                const fileCard = this.createFileCard(file);
                filesGrid.appendChild(fileCard);
            });
        }
        
        if (filesList) {
            filesList.innerHTML = '';
            files.forEach(file => {
                const fileItem = this.createFileListItem(file);
                filesList.appendChild(fileItem);
            });
        }
    }

    createFileCard(file) {
        const card = document.createElement('div');
        card.className = 'file-card';
        
        const fileExtension = this.getFileExtension(file.original_filename);
        const fileIcon = this.getFileTypeIcon(fileExtension);
        const tags = file.tags ? file.tags.split(',').map(tag => tag.trim()) : [];
        
        card.innerHTML = `
            <div class="file-header">
                <div class="file-type-icon">${fileIcon}</div>
                <div class="file-actions">
                    <button class="file-action" onclick="fileManager.downloadFile(${file.id})" title="Download">
                        <svg viewBox="0 0 24 24" fill="currentColor" width="16" height="16">
                            <path d="M5,20H19V18H5M19,9H15V3H9V9H5L12,16L19,9Z"/>
                        </svg>
                    </button>
                    <button class="file-action" onclick="fileManager.editFile(${file.id})" title="Edit">
                        <svg viewBox="0 0 24 24" fill="currentColor" width="16" height="16">
                            <path d="M20.71,7.04C21.1,6.65 21.1,6 20.71,5.63L18.37,3.29C18,2.9 17.35,2.9 16.96,3.29L15.12,5.12L18.87,8.87M3,17.25V21H6.75L17.81,9.93L14.06,6.18L3,17.25Z"/>
                        </svg>
                    </button>
                    <button class="file-action danger" onclick="fileManager.deleteFile(${file.id})" title="Delete">
                        <svg viewBox="0 0 24 24" fill="currentColor" width="16" height="16">
                            <path d="M19,4H15.5L14.5,3H9.5L8.5,4H5V6H19M6,19A2,2 0 0,0 8,21H16A2,2 0 0,0 18,19V7H6V19Z"/>
                        </svg>
                    </button>
                </div>
            </div>
            <div class="file-details">
                <h3>${file.original_filename}</h3>
                <p class="file-description">${file.description || 'No description'}</p>
                <div class="file-meta">
                    <span>${this.formatDate(file.date_added)}</span>
                    <span>${fileExtension.toUpperCase()}</span>
                </div>
                ${tags.length > 0 ? `
                    <div class="file-tags">
                        ${tags.map(tag => `<span class="tag">${tag}</span>`).join('')}
                    </div>
                ` : ''}
            </div>
        `;
        
        return card;
    }

    createFileListItem(file) {
        const item = document.createElement('div');
        item.className = 'file-list-item';
        
        const fileExtension = this.getFileExtension(file.original_filename);
        const fileIcon = this.getFileTypeIcon(fileExtension);
        const tags = file.tags ? file.tags.split(',').map(tag => tag.trim()) : [];
        
        item.innerHTML = `
            <div class="file-type-icon">${fileIcon}</div>
            <div>
                <div class="file-name">${file.original_filename}</div>
                <div class="file-description">${file.description || 'No description'}</div>
                ${tags.length > 0 ? `
                    <div class="file-tags">
                        ${tags.map(tag => `<span class="tag">${tag}</span>`).join('')}
                    </div>
                ` : ''}
            </div>
            <div>${this.formatDate(file.date_added)}</div>
            <div>${fileExtension.toUpperCase()}</div>
            <div class="file-actions">
                <button class="file-action" onclick="fileManager.downloadFile(${file.id})" title="Download">
                    <svg viewBox="0 0 24 24" fill="currentColor" width="16" height="16">
                        <path d="M5,20H19V18H5M19,9H15V3H9V9H5L12,16L19,9Z"/>
                    </svg>
                </button>
                <button class="file-action" onclick="fileManager.editFile(${file.id})" title="Edit">
                    <svg viewBox="0 0 24 24" fill="currentColor" width="16" height="16">
                        <path d="M20.71,7.04C21.1,6.65 21.1,6 20.71,5.63L18.37,3.29C18,2.9 17.35,2.9 16.96,3.29L15.12,5.12L18.87,8.87M3,17.25V21H6.75L17.81,9.93L14.06,6.18L3,17.25Z"/>
                    </svg>
                </button>
                <button class="file-action danger" onclick="fileManager.deleteFile(${file.id})" title="Delete">
                    <svg viewBox="0 0 24 24" fill="currentColor" width="16" height="16">
                        <path d="M19,4H15.5L14.5,3H9.5L8.5,4H5V6H19M6,19A2,2 0 0,0 8,21H16A2,2 0 0,0 18,19V7H6V19Z"/>
                    </svg>
                </button>
            </div>
        `;
        
        return item;
    }

    updateFilesCount() {
        const countElement = document.querySelector('.files-count');
        if (countElement && this.files) {
            countElement.textContent = this.files.length;
        }
    }

    getFileExtension(filename) {
        return filename.split('.').pop().toLowerCase();
    }

    getFileTypeIcon(extension) {
        const iconMap = {
            'pdf': 'PDF',
            'doc': 'DOC',
            'docx': 'DOC',
            'txt': 'TXT',
            'jpg': 'IMG',
            'jpeg': 'IMG',
            'png': 'IMG',
            'gif': 'IMG',
            'mp4': 'VID',
            'avi': 'VID',
            'mp3': 'AUD',
            'wav': 'AUD',
            'zip': 'ZIP',
            'rar': 'RAR',
            'py': 'PY',
            'js': 'JS',
            'html': 'HTM',
            'css': 'CSS',
            'json': 'JSN'
        };
        
        return iconMap[extension] || 'FILE';
    }

    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    formatDate(dateString) {
        const date = new Date(dateString);
        return date.toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    }

    downloadFile(fileId) {
        window.location.href = `/download/${fileId}`;
    }

    editFile(fileId) {
        window.location.href = `/edit/${fileId}`;
    }

    async deleteFile(fileId) {
        if (!confirm('Are you sure you want to delete this file?')) {
            return;
        }

        try {
            const response = await fetch(`/delete/${fileId}`, {
                method: 'POST'
            });

            if (response.ok) {
                this.showNotification('File deleted successfully', 'success');
                this.loadFiles();
            } else {
                throw new Error('Failed to delete file');
            }
        } catch (error) {
            this.showNotification('Error deleting file: ' + error.message, 'error');
        }
    }

    createBackup() {
        window.location.href = '/backup';
        this.showNotification('Backup created successfully', 'success');
    }

    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.innerHTML = `
            <div>${message}</div>
            <button class="modal-close" onclick="this.parentElement.remove()">×</button>
        `;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.classList.add('show');
        }, 100);
        
        setTimeout(() => {
            notification.classList.remove('show');
            setTimeout(() => {
                notification.remove();
            }, 300);
        }, 3000);
    }
}

// Initialize the file manager when the page loads
let fileManager;
document.addEventListener('DOMContentLoaded', () => {
    fileManager = new FileManagerPro();
});

// Global functions for inline event handlers
window.fileManager = fileManager;

