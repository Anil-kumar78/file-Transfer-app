# Secure File Transfer Application

A secure file transfer application with end-to-end encryption, built using Python Flask and modern web technologies.

## Features

- End-to-end encryption using Fernet (symmetric encryption)
- User authentication and authorization
- Secure file upload and download
- Drag-and-drop file interface
- Access control and audit logging
- Modern, responsive UI
- Real-time file management

## Security Features

- Files are encrypted before storage using Fernet encryption
- Each file has its own unique encryption key
- Passwords are securely hashed using Werkzeug's security functions
- JWT-based authentication
- Access control to ensure users can only access their own files
- Comprehensive audit logging of all file operations

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd secure-file-transfer
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Running the Application

1. Start the Flask server:
```bash
python app.py
```

2. Open your web browser and navigate to:
```
http://localhost:5000
```

## Usage

1. Register a new account or login with existing credentials
2. Use the drag-and-drop interface or click to select files for upload
3. View your uploaded files in the dashboard
4. Download files using the download button
5. Monitor file access through the audit logs

## Security Considerations

- The application uses Fernet symmetric encryption for file security
- Each file is encrypted with a unique key
- Files are stored in an encrypted format on the server
- Access is controlled through JWT tokens
- All file operations are logged for audit purposes

## API Endpoints

- POST `/register` - Register a new user
- POST `/login` - Authenticate and get JWT token
- POST `/upload` - Upload a file (requires authentication)
- GET `/download/<file_id>` - Download a file (requires authentication)
- GET `/files` - List user's files (requires authentication)
- GET `/logs` - View access logs (requires authentication)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 