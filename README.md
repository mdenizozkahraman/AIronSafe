# AIronSafe - Web Application Security Testing Platform

AIronSafe is a comprehensive web application security testing platform that combines Static Application Security Testing (SAST) and Dynamic Application Security Testing (DAST) capabilities in a modern, user-friendly interface.

## 🚀 Features

### Static Application Security Testing (SAST)
- Upload and analyze source code for security vulnerabilities
- Support for multiple file formats (.zip, .rar, .7zip, .tar, .gz)
- Real-time vulnerability detection and reporting
- Severity-based vulnerability categorization
- Detailed vulnerability descriptions and counts

### Dynamic Application Security Testing (DAST)
- Web application security scanning
- URL-based target specification
- Real-time vulnerability detection
- Comprehensive security assessment
- Detailed scan reports with timing information

### Dashboard
- Overview of all security testing activities
- Real-time statistics and metrics
- Recent activity tracking
- Intuitive navigation
- Responsive design for all devices

## 🛠️ Technology Stack

- **Frontend**: React.js
- **Backend**: Flask (Python)
- **Database**: SQLAlchemy
- **Authentication**: JWT
- **UI Framework**: Custom CSS with modern design principles

## 📋 Prerequisites

- Node.js (v16 or higher)
- Python 3.8 or higher
- npm or yarn package manager

## 🔧 Installation

### Frontend Setup

1. Navigate to the frontend directory:
```bash
cd frontend
```

2. Install dependencies:
```bash
npm install
```

3. Start the development server:
```bash
npm start
```

### Backend Setup

1. Navigate to the backend directory:
```bash
cd backend
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Start the Flask server:
```bash
python app.py
```

## 🔒 Security Features

- JWT-based authentication
- Secure password handling
- CSRF protection
- XSS prevention
- SQL injection protection
- Security headers implementation

## 🎯 Usage

1. Register a new account or login with existing credentials
2. Navigate to SAST for source code analysis
3. Use DAST for web application scanning
4. View results and reports in the dashboard
5. Track security issues and their resolution

## 📱 Responsive Design

AIronSafe is fully responsive and works seamlessly on:
- Desktop computers
- Tablets
- Mobile devices

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 📞 Support

For support, please open an issue in the GitHub repository or contact the development team.

## ✨ Acknowledgments

- React.js community
- Flask community
- All contributors and testers

---
© 2025 AIronSafe. All Rights Reserved.

## 🚀 How to Run with Docker
### 1. Clone the repository:
```bash
git clone https://github.com/mdenizozkahraman/AIronSafe.git
cd AIronSafe

docker-compose up --build

