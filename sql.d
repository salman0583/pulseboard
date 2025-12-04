CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    full_name VARCHAR(255),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);


CREATE TABLE refresh_tokens (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    jti VARCHAR(64) NOT NULL,          -- unique id from JWT (jti claim)
    username VARCHAR(150) NOT NULL,    -- your app's username / user key
    is_revoked TINYINT(1) NOT NULL DEFAULT 0,
    issued_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_refresh_jti (jti),
    KEY idx_refresh_username (username),
    KEY idx_refresh_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


CREATE TABLE IF NOT EXISTS otp_codes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(150) NOT NULL,
    otp_code VARCHAR(10) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- USERS table already exists (email, username, ...)

-- 1) Workspaces
CREATE TABLE IF NOT EXISTS workspaces (
  id INT PRIMARY KEY AUTO_INCREMENT,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  created_by VARCHAR(255) NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_workspaces_created_by ON workspaces(created_by);

-- 2) Workspace Members
CREATE TABLE IF NOT EXISTS workspace_members (
  id INT PRIMARY KEY AUTO_INCREMENT,
  workspace_id INT NOT NULL,
  user_email VARCHAR(255) NOT NULL,
  role VARCHAR(50) DEFAULT 'member',
  added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY unique_member (workspace_id, user_email),
  INDEX idx_members_ws (workspace_id),
  INDEX idx_members_user (user_email)
);

-- 3) Channels
CREATE TABLE IF NOT EXISTS channels (
  id INT PRIMARY KEY AUTO_INCREMENT,
  workspace_id INT NOT NULL,
  name VARCHAR(255) NOT NULL,
  is_private TINYINT(1) DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY unique_channel (workspace_id, name),
  INDEX idx_channels_ws (workspace_id)
);

-- 4) Messages
CREATE TABLE IF NOT EXISTS messages (
  id INT PRIMARY KEY AUTO_INCREMENT,
  channel_id INT NOT NULL,
  sender_email VARCHAR(255) NOT NULL,
  body TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_messages_channel_time (channel_id, created_at)
);

-- 5) Read Receipts
CREATE TABLE IF NOT EXISTS read_receipts (
  id INT PRIMARY KEY AUTO_INCREMENT,
  message_id INT NOT NULL,
  user_email VARCHAR(255) NOT NULL,
  read_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY unique_receipt (message_id, user_email)
);

-- 6) Activity Feed
CREATE TABLE IF NOT EXISTS activities (
  id INT PRIMARY KEY AUTO_INCREMENT,
  workspace_id INT NOT NULL,
  actor_email VARCHAR(255) NOT NULL,
  type VARCHAR(100) NOT NULL,
  ref_id INT DEFAULT NULL,
  summary TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_activities_ws_time (workspace_id, created_at)
);

-- 7) Presence
CREATE TABLE IF NOT EXISTS presence (
  user_email VARCHAR(255) PRIMARY KEY,
  status VARCHAR(20) NOT NULL,
  last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 8) Notifications
CREATE TABLE IF NOT EXISTS notifications (
  id INT PRIMARY KEY AUTO_INCREMENT,
  user_email VARCHAR(255) NOT NULL,
  type VARCHAR(100) NOT NULL,
  payload JSON DEFAULT NULL,
  is_read TINYINT(1) DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_notifications_user_time (user_email, created_at)
);

CREATE TABLE IF NOT EXISTS message_reads (
    id INT AUTO_INCREMENT PRIMARY KEY,
    message_id INT NOT NULL,
    reader_email VARCHAR(255) NOT NULL,
    read_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE KEY unique_read (message_id, reader_email),

    CONSTRAINT fk_message_reads_message
        FOREIGN KEY (message_id)
        REFERENCES messages(id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
);



CREATE TABLE IF NOT EXISTS notifications (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_email VARCHAR(255) NOT NULL,     -- who receives the notification
    type VARCHAR(50) NOT NULL,            -- e.g., mention, task, system, activity
    payload JSON NOT NULL,                -- dynamic data (message_id, channel_id, etc.)
    is_read TINYINT(1) NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_notifications_user (user_email),
    INDEX idx_notifications_user_unread (user_email, is_read)
);



CREATE TABLE IF NOT EXISTS tasks (
  id INT PRIMARY KEY AUTO_INCREMENT,
  workspace_id INT NOT NULL,
  created_by VARCHAR(255) NOT NULL,
  title VARCHAR(255) NOT NULL,
  description TEXT,
  status VARCHAR(50) DEFAULT 'todo',  -- todo, doing, done
  assignee_email VARCHAR(255),
  priority VARCHAR(20) DEFAULT 'normal', -- low, normal, high
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
CREATE INDEX idx_tasks_ws ON tasks(workspace_id);
CREATE INDEX idx_tasks_assignee ON tasks(assignee_email);




CREATE TABLE github_repos (
    id INT AUTO_INCREMENT PRIMARY KEY,
    workspace_id INT NOT NULL,
    repo_full_name VARCHAR(255) NOT NULL,   -- e.g. 'org/repo'
    events_mask VARCHAR(100) NOT NULL DEFAULT 'push,pr,issues',
    webhook_secret VARCHAR(255) NOT NULL,
    is_active TINYINT(1) DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    UNIQUE KEY uniq_ws_repo (workspace_id, repo_full_name),
    CONSTRAINT fk_github_repos_workspace
        FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
        ON DELETE CASCADE
);














UPDATE users
SET is_admin = 1, can_create_workspace = 1
WHERE email = 'your_user_email@example.com';
