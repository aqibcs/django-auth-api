# Django User Authentication API
This project provides a RESTful API for user authentication and management in a Django application. It includes endpoints for user registration, login, profile retrieval, password change, and password reset functionalities.

## Installation
1. **Install dependencies:**
```bash
pip install -r requirements.txt
```

## API Endpoints
### Register User
- **URL:** `/api/user/register/`
- **Method:** `POST`
- **Payload:**
```json
{
  "email": "user@example.com",
  "name": "John Doe",
  "password": "your_password",
  "password2": "your_password_confirmation",
  "tc": true
}
```
- **Response:**
```json
{
  "token": {
    "refresh": "your_refresh_token",
    "access": "your_access_token"
  },
  "message": "Registration Successful"
}
```

### Login User
- **URL:** `/api/user/login/`
- **Method:** `POST`
- **Payload:**
```json
{
  "email": "user@example.com",
  "password": "your_password"
}
```
- **Response:**
```json
{
  "token": {
    "refresh": "your_refresh_token",
    "access": "your_access_token"
  },
  "message": "Login Success"
}
```

### User Profile
- **URL:** `/api/user/profile/`
- **Method:** `GET`
- **Headers:** `Authorization: Bearer Your_access_token`
- **Response:**
```json
{
  "id": 1,
  "email": "user@example.com",
  "name": "John Doe"
}
```

### Change Password
- **URL:** `/api/user/change-password/`
- **Method:** `POST`
- **Headers:** `Authorization: Bearer your_access_token`
- **Payload:**
```json
{
  "password": "your_new_password",
  "password2": "your_new_password_confirmation"
}
```
- **Response:**
```json
{
  "message": "Password Changed Successfully"
}
```

### Send Password Reset Email
- **URL:** `/api/user/send-reset-password-email/`
- **Method:** `POST`
- **Payload:**
```json
{
  "email": "user@example.com"
}
```
- **Response:**
```json
{
  "message": "Password Reset link sent. Please check your Email"
}
```

### Reset Password
- **URL:** `api/user/reset-password/<uid>/<token>/`
- **Method:** `POST`
- **Payload:**
```json
{
  "password": "your_new_password",
  "password2": "your_new_password_confirmation"
}
```
- **Response:**
```json
{
  "message": "Password Reset Successfully"
}
```