# 🔒 Secure Cloud Storage

A secure cloud-based file storage web application developed using **Flask** and **SQLite**, designed to provide authenticated users with a safe environment for storing, managing, and accessing files. The application incorporates modern security features such as OTP-based verification, password hashing, file encryption, and role-based administration.

---

## 📌 Overview

Secure Cloud Storage enables users to upload, download, and manage files securely through an intuitive web interface. The application emphasizes data security by implementing authentication, encrypted file storage, and administrative monitoring.

---

## ✨ Features

### 👤 User Module

* User Registration with email validation
* Secure Login System
* OTP-based Email Verification
* Password Hashing for enhanced security
* Upload Files
* Download Files
* Delete Files
* Storage Usage Dashboard
* Session Management
* User Profile Management

### 🔐 Security Features

* OTP Authentication
* Secure Password Storage
* Encrypted File Storage
* File Size Validation
* Session Security
* Access Control
* Protected Routes
* Input Validation

### 🛠️ Admin Module

* Admin Login
* Dashboard Overview
* View Registered Users
* View Uploaded Files
* Monitor Storage Usage
* Delete Users
* Delete Files
* Secure Admin Logout

---

## 🏗️ Tech Stack

| Category        | Technology                        |
| --------------- | --------------------------------- |
| Backend         | Python, Flask                     |
| Frontend        | HTML5, CSS3, JavaScript           |
| Database        | SQLite                            |
| Authentication  | OTP Verification                  |
| Security        | Password Hashing, File Encryption |
| Version Control | Git & GitHub                      |

---

## 📂 Project Structure

```text
secure-cloud-storage/
│
├── app.py
├── database.py
├── encryption.py
├── otp.py
├── requirements.txt
├── database.db
├── uploads/
├── encrypted_files/
├── templates/
├── static/
└── README.md
```

---

## 🚀 Installation

### Clone the repository

```bash
git clone https://github.com/494-rakshu/secure-cloud-storage.git
```

### Navigate to the project

```bash
cd secure-cloud-storage
```

### Create a virtual environment

```bash
python -m venv venv
```

### Activate the virtual environment

**Windows**

```bash
venv\Scripts\activate
```

**Linux / macOS**

```bash
source venv/bin/activate
```

### Install dependencies

```bash
pip install -r requirements.txt
```

### Run the application

```bash
python app.py
```

---

## 🔒 Security Highlights

* Passwords are securely hashed before storage.
* OTP verification is required for authentication.
* Uploaded files are encrypted before being stored.
* Protected user sessions prevent unauthorized access.
* Access is restricted using role-based authentication.
* Input validation minimizes common security vulnerabilities.

---

## 📸 Screenshots

Add screenshots of the following pages:

* Home Page
* User Login
* Registration
* OTP Verification
* User Dashboard
* File Upload
* Storage Dashboard
* Admin Login
* Admin Dashboard

---

## 🌟 Future Enhancements

* Cloud storage integration (AWS S3 / Azure Blob Storage)
* Multi-factor authentication (MFA)
* File sharing with secure links
* Folder management
* Password reset via email
* User activity logs
* Audit trail
* Dark mode
* Responsive mobile interface

---

## 🎯 Learning Outcomes

This project strengthened my understanding of:

* Flask Web Development
* Python Backend Programming
* SQLite Database Management
* User Authentication
* OTP Integration
* File Encryption
* Session Management
* Web Security Best Practices
* Git & GitHub Workflow

---

## 👩‍💻 Author - Rakshita Reddy

**Skills**

* Python
* SQL
* Flask
* HTML
* CSS
* JavaScript
* Cloud Computing
* Cybersecurity

---

## ⭐ Support

If you found this project useful, consider giving it a **⭐ Star** on GitHub.
