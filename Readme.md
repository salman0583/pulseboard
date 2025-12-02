# pluseboard Backend API

A Django-based collaborative workspace platform with real-time messaging, activity tracking, and analytics.

---

## 📋 Table of Contents

- [Features](#features)
- [Tech Stack](#tech-stack)
- [Installation](#installation)
- [Configuration](#configuration)
- [Authentication Workflow](#authentication-workflow)
- [API Endpoints](#api-endpoints)
- [WebSocket Connections](#websocket-connections)
- [Usage Examples](#usage-examples)
- [Troubleshooting](#troubleshooting)

---

## ✨ Features

- **Secure Authentication**: JWT-based auth with email OTP verification
- **Workspace Management**: Create and manage collaborative workspaces
- **Channel System**: Public and private channels for organized communication
- **Real-time Messaging**: WebSocket-powered instant messaging
- **Activity Feed**: Live activity tracking across workspaces
- **User Presence**: Real-time online/offline status
- **Push Notifications**: Instant user notifications
- **Analytics Dashboard**: Message metrics and active user statistics

---

## 🛠 Tech Stack

- **Framework**: Django 4.x with Django Channels
- **Database**: MySQL
- **Authentication**: JWT tokens (PyJWT)
- **WebSockets**: Django Channels for real-time features
- **Email**: SMTP (Gmail/custom)

---

## 🚀 Installation

### Prerequisites

- Python 3.8 or higher
- MySQL 5.7 or higher
- pip package manager

### Setup Steps

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd backend
   ```

2. **Create and activate virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables** (see Configuration below)

5. **Create database**
   ```sql
   CREATE DATABASE techaccess_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
   ```

6. **Run migrations**
   ```bash
   python manage.py migrate
   ```

7. **Start the development server**
   ```bash
   python manage.py runserver
   ```

Server will be available at: `http://localhost:8000`

---

## ⚙️ Configuration

Create a `.env` file in the project root with the following variables:

```bash
# Database Configuration
DB_HOST=localhost
DB_PORT=3306
DB_NAME=techaccess_db
DB_USER=your_database_user
DB_PASSWORD=your_database_password

# JWT Secret Key
JWT_SECRET_KEY=your-secure-random-secret-key

# Email Configuration (Gmail Example)
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-gmail-app-password

# Django Settings
DEBUG=True
SECRET_KEY=your-django-secret-key
```

### Gmail Setup for OTP

1. Enable 2-Step Verification in your Google Account
2. Generate an App Password: [Google App Passwords](https://myaccount.google.com/apppasswords)
3. Use the generated 16-character password as `EMAIL_HOST_PASSWORD`

---

## 🔐 Authentication Workflow

### Step-by-Step Flow

```
1. User Registration
   ↓
2. Request OTP (sent to email)
   ↓
3. Verify OTP + Login
   ↓
4. Receive Auth Tokens (via HTTPOnly cookies)
   ↓
5. Make Authenticated Requests
   ↓
6. Auto Token Refresh (when needed)
   ↓
7. Logout (revoke tokens)
```

### Token System

The backend uses three types of JWT tokens stored in HTTPOnly cookies:

- **Access Token** (15 minutes): Used for API authentication
- **Refresh Token** (30 days): Used to get new access tokens
- **ID Token** (15 minutes): Contains user profile information

All tokens are automatically included in requests via cookies - no manual header management needed.

---

## 🔌 API Endpoints

### Base URL
```
http://localhost:8000/api
```

---

### 1️⃣ Authentication

#### Register New User
```http
POST /api/register/
Content-Type: application/json

{
  "username": "johndoe",
  "password": "securePassword123",
  "email": "john@example.com",
  "full_name": "John Doe"
}
```

**Response:**
```json
{
  "status": "success",
  "message": "User registered successfully!"
}
```

---

#### Request OTP
```http
POST /api/request-otp/
Content-Type: application/json

{
  "email": "john@example.com"
}
```

**Response:**
```json
{
  "status": "success",
  "message": "OTP sent to john@example.com"
}
```

**Note**: Check your email for the 6-digit OTP code (valid for 5 minutes).

---

#### Verify OTP & Login
```http
POST /api/verify-otp/
Content-Type: application/json

{
  "email": "john@example.com",
  "otp": "123456"
}
```

**Response:**
```json
{
  "status": "success",
  "message": "Login successful!"
}
```

**Sets cookies**: `access_token`, `refresh_token`, `id_token`

---

#### Logout
```http
POST /api/logout/
```

**Response:**
```json
{
  "status": "success",
  "message": "Logged out"
}
```

**Clears all auth cookies and revokes refresh token.**

---

### 2️⃣ Workspaces

#### Get All Workspaces
```http
GET /api/workspaces/
```

**Response:**
```json
{
  "status": "success",
  "data": [
    {
      "id": 1,
      "name": "Engineering Team",
      "description": "Main engineering workspace",
      "created_by": "john@example.com",
      "created_at": "2025-01-15T10:30:00"
    }
  ]
}
```

---

#### Create Workspace
```http
POST /api/workspaces/
Content-Type: application/json

{
  "name": "Marketing Team",
  "description": "Marketing collaboration space"
}
```

**Response:**
```json
{
  "status": "success",
  "workspace_id": 2
}
```

---

### 3️⃣ Channels

#### Get Channels in Workspace
```http
GET /api/channels/?workspace_id=1
```

**Response:**
```json
{
  "status": "success",
  "data": [
    {
      "id": 1,
      "workspace_id": 1,
      "name": "general",
      "is_private": 0,
      "created_at": "2025-01-15T10:35:00"
    }
  ]
}
```

---

#### Create Channel
```http
POST /api/channels/
Content-Type: application/json

{
  "workspace_id": 1,
  "name": "random",
  "is_private": false
}
```

**Response:**
```json
{
  "status": "success",
  "channel_id": 2
}
```

---

### 4️⃣ Messages

#### Get Messages in Channel
```http
GET /api/messages/?channel_id=1
```

**Response:**
```json
{
  "status": "success",
  "data": [
    {
      "id": 1,
      "sender_email": "john@example.com",
      "body": "Hello team!",
      "created_at": "2025-01-15T11:00:00"
    }
  ]
}
```

---

#### Send Message
```http
POST /api/messages/
Content-Type: application/json

{
  "channel_id": 1,
  "body": "Hello everyone!"
}
```

**Response:**
```json
{
  "status": "success",
  "message_id": 5
}
```

---

### 5️⃣ Analytics

#### Messages Per Day (Last 14 Days)
```http
POST /api/metrics/messages-per-day
Content-Type: application/json

{
  "workspace_id": 1
}
```

**Response:**
```json
{
  "status": "success",
  "data": [
    {"day": "2025-01-01", "count": 45},
    {"day": "2025-01-02", "count": 67}
  ]
}
```

---

#### Active Users Count
```http
POST /api/metrics/active-users
Content-Type: application/json

{
  "workspace_id": 1,
  "minutes": 15
}
```

**Response:**
```json
{
  "status": "success",
  "data": {
    "active_count": 8
  }
}
```

---

### 6️⃣ Activity Feed

#### Get Recent Activities
```http
POST /api/activities/
Content-Type: application/json

{
  "workspace_id": 1,
  "limit": 50
}
```

**Response:**
```json
{
  "status": "success",
  "data": [
    {
      "id": 1,
      "actor_email": "john@example.com",
      "type": "message_sent",
      "ref_id": 5,
      "summary": "John sent a message in #general",
      "created_at": "2025-01-15T11:00:00"
    }
  ]
}
```

---

### 7️⃣ Utility

#### Refresh Token Endpoint
```http
POST /api/refresh/
```

**Purpose**: Call before establishing WebSocket connections to ensure fresh access token.

**Response:** `204 No Content` (automatically refreshes cookies if needed)

---

## 🔄 WebSocket Connections

### Connection Format
```
ws://localhost:8000/ws/<endpoint>/?token=<access_token>
```

### Available WebSocket Endpoints

| Endpoint | Purpose |
|----------|---------|
| `/ws/chat/` | Real-time messaging |
| `/ws/activity/` | Live activity updates |
| `/ws/presence/` | User online/offline status |
| `/ws/notifications/` | Push notifications |

---

### 1️⃣ Chat WebSocket

**Connect:**
```javascript
const ws = new WebSocket('ws://localhost:8000/ws/chat/?token=' + accessToken);
```

**Events:**

**Join a channel:**
```javascript
ws.send(JSON.stringify({
  type: 'join_channel',
  channel_id: 1
}));
```

**Send a message:**
```javascript
ws.send(JSON.stringify({
  type: 'send_message',
  channel_id: 1,
  body: 'Hello everyone!'
}));
```

**Receive messages:**
```javascript
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  
  if (data.type === 'new_message') {
    console.log('New message:', data.message);
    // data.message contains: id, sender_email, body, created_at
  }
};
```

---

### 2️⃣ Activity Feed WebSocket

**Connect:**
```javascript
const ws = new WebSocket('ws://localhost:8000/ws/activity/?token=' + accessToken);
```

**Subscribe to workspace:**
```javascript
ws.send(JSON.stringify({
  type: 'subscribe',
  workspace_id: 1
}));
```

**Receive updates:**
```javascript
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  
  if (data.type === 'activity_update') {
    console.log('New activity:', data.activity);
  }
};
```

---

### 3️⃣ Presence WebSocket

**Connect:**
```javascript
const ws = new WebSocket('ws://localhost:8000/ws/presence/?token=' + accessToken);
```

**Send heartbeat (every 30 seconds):**
```javascript
setInterval(() => {
  ws.send(JSON.stringify({
    type: 'heartbeat',
    status: 'online'
  }));
}, 30000);
```

**Receive presence updates:**
```javascript
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  
  if (data.type === 'presence_update') {
    console.log('User status changed:', data);
    // data contains: user_email, status (online/offline/idle)
  }
};
```

---

### 4️⃣ Notifications WebSocket

**Connect:**
```javascript
const ws = new WebSocket('ws://localhost:8000/ws/notifications/?token=' + accessToken);
```

**Subscribe:**
```javascript
ws.send(JSON.stringify({
  type: 'subscribe'
}));
```

**Receive notifications:**
```javascript
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  
  if (data.type === 'notification') {
    console.log('New notification:', data.message);
  }
};
```

---

## 📖 Usage Examples

### Complete Client Flow Example

```javascript
// 1. Register
await fetch('http://localhost:8000/api/register/', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({
    username: 'alice',
    password: 'securePass123',
    email: 'alice@example.com',
    full_name: 'Alice Johnson'
  })
});

// 2. Request OTP
await fetch('http://localhost:8000/api/request-otp/', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({email: 'alice@example.com'})
});

// 3. Verify OTP (after receiving email)
const loginResponse = await fetch('http://localhost:8000/api/verify-otp/', {
  method: 'POST',
  credentials: 'include', // Important: include cookies
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({
    email: 'alice@example.com',
    otp: '123456'
  })
});

// 4. Create Workspace
const workspaceResponse = await fetch('http://localhost:8000/api/workspaces/', {
  method: 'POST',
  credentials: 'include', // Include auth cookies
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({
    name: 'My Team',
    description: 'Team workspace'
  })
});

// 5. Create Channel
await fetch('http://localhost:8000/api/channels/', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({
    workspace_id: 1,
    name: 'general',
    is_private: false
  })
});

// 6. Connect to WebSocket
const ws = new WebSocket('ws://localhost:8000/ws/chat/?token=' + accessToken);

ws.onopen = () => {
  // Join channel
  ws.send(JSON.stringify({
    type: 'join_channel',
    channel_id: 1
  }));
  
  // Send message
  ws.send(JSON.stringify({
    type: 'send_message',
    channel_id: 1,
    body: 'Hello team!'
  }));
};

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Received:', data);
};
```

---

## 🔒 Security Notes

### For Clients

1. **Cookies**: All authentication is handled via HTTPOnly cookies
   - Always include `credentials: 'include'` in fetch requests
   - Cookies are automatically sent with requests

2. **Token Expiration**: Access tokens expire after 15 minutes
   - Backend automatically refreshes when needed
   - No manual token management required

3. **OTP Security**: OTP codes expire after 5 minutes
   - Each OTP can only be used once
   - Request a new OTP if expired

4. **CORS**: Configure allowed origins in production
   - Contact backend admin to whitelist your domain

---

## 🐛 Troubleshooting

### Common Issues

**Issue: OTP email not received**
- Check spam/junk folder
- Verify email address is correct
- Wait 1-2 minutes for delivery
- Request new OTP if needed

**Issue: "Invalid or expired token" error**
- Ensure `credentials: 'include'` is set in fetch
- Call `/api/refresh/` before making requests
- Re-login if refresh token expired

**Issue: WebSocket connection failed**
- Verify access token is valid
- Call `/api/refresh/` before connecting
- Check WebSocket URL format
- Ensure server is running

**Issue: CORS errors in browser**
- Contact backend admin to whitelist your domain
- Ensure `credentials: 'include'` is set

**Issue: "POST method required" error**
- Check HTTP method (GET vs POST)
- Verify endpoint URL is correct

---

## 📞 Support

For issues or questions:
- Check logs on the server side
- Review API response error messages
- Verify request format matches documentation

---

## 🚀 Production Deployment

When deploying to production:
- Set `DEBUG = False`
- Use HTTPS (wss:// for WebSockets)
- Configure proper CORS settings
- Use strong JWT secret keys
- Enable database connection pooling
- Set up Redis for WebSocket scaling

---

**Last Updated**: November 2025