🚀 Pulsboard Backend Platform
Real-Time Collaboration • Secure • Scalable
</div>
🌟 Overview

Pulsboard is a modern real-time collaboration backend built to support teams working together across projects, conversations, and tasks.

It combines secure APIs with live WebSocket communication to deliver a smooth, Slack-like experience enhanced with analytics and integrations.

🎯 Why Pulsboard?

✔ Centralized team communication
✔ Live collaboration with instant updates
✔ Clear task ownership & tracking
✔ Transparent activity history
✔ GitHub development visibility
✔ Enterprise-grade security

🧩 Key Capabilities
🔐 Authentication & Security

Email-based OTP login

JWT session management:

Access Token

Refresh Token (revocable)

Cookie-based authentication

Secure WebSocket authentication

Strict role-based permission checks

🏢 Workspace Management

Create and manage multiple workspaces

Role-based access control:

🛡 Admin – full platform access

👑 Workspace Owner – workspace control

👤 Member – participation access

Add, remove, and manage members

💬 Real-Time Communication
📢 Channels

Team-wide channel discussions

Persistent message history

Typing indicators

Read receipts

Real-time updates via WebSockets

🔒 Direct Messages

Private 1-to-1 conversations

Edit and delete messages

Real-time delivery and updates

Workspace-scoped access

✅ Tasks & Project Tracking

Create, update, assign, and delete tasks

Task priorities and status tracking

Fine-grained permissions:

Admin

Workspace Owner

Task Creator

Task Assignee

All task actions logged automatically

📢 Workspace Updates

Share structured project updates

Edit or remove updates

Updates appear in activity feed

Ideal for announcements and progress reports

📰 Activity Feed

Central timeline of:

Messages

Task events

Workspace updates

GitHub activity

Available via REST API

Live updates via WebSockets

🔔 Notifications

Stored notifications for reliability

Real-time push notifications

Mark individual or all as read

Triggered by mentions, DMs, tasks, and system events

🟢 Presence System

Tracks user state:

🟢 Online

🟡 Idle

⚫ Offline

Live presence updates

Powers analytics and UI indicators

📊 Metrics & Analytics

Messages per day

Active users (presence-based)

Project Story:

Auto-generated, human-readable summary of workspace activity

🔗 GitHub Integration

Connect repositories to workspaces

Supported events:

Pushes

Pull Requests

Issues

Secure webhook validation (HMAC)

GitHub events appear in activity feed

🏗 Technical Architecture
Layer	Technology
Backend Framework	Django
Real-Time Layer	Django Channels (ASGI)
Database	MySQL
Authentication	Custom JWT
Communication	REST APIs + WebSockets
🔁 Authentication Flow (Simplified)
Register → Request OTP → Verify OTP
        ↓
   Access + Refresh Tokens
        ↓
 REST APIs & WebSockets


Tokens stored securely in cookies

Same session used across HTTP and WebSockets

🌐 API Design
🔹 REST APIs

Used for:

Authentication

Workspaces & members

Tasks & updates

Metrics & analytics

Admin controls

GitHub integrations

All protected endpoints require authentication.

🔹 WebSocket Services

Used for:

Live chat

Direct messages

Activity feed

Presence tracking

Notifications

Authenticated using cookies or token fallback.

🚀 Deployment Ready

Stateless backend

Token-based authentication

Horizontal scaling supported

Compatible with:

Docker

Nginx

Daphne / Uvicorn (ASGI)

🧪 Testing

REST APIs: Postman

WebSockets:

Postman (WebSocket mode)

Browser DevTools

WebSocket clients

🔐 Security Highlights

OTP expiration enforced

Refresh token revocation

WebSocket auth validation on connect

Role-based permission checks everywhere

GitHub secrets never exposed

🎯 Ideal Use Cases

Team collaboration platforms

Internal enterprise tools

Startup communication systems

Project management dashboards

<div align="center">
🧠 Built for real-time collaboration, security, and scale
</div>
📄 License
MIT License