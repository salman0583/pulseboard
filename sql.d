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



-- 7) Presence                        
CREATE TABLE IF NOT EXISTS presence (
  user_email VARCHAR(255) PRIMARY KEY,
  status VARCHAR(20) NOT NULL,
  last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS notifications (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    user_email VARCHAR(255) NOT NULL,

    -- semantic type: task_assigned, task_status_changed, dm, system
    type VARCHAR(50) NOT NULL,

    -- full structured data for frontend
    payload JSON NOT NULL,

    is_read TINYINT(1) NOT NULL DEFAULT 0,

    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_notifications_user (user_email),
    INDEX idx_notifications_user_unread (user_email, is_read),
    INDEX idx_notifications_type (type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;



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

CREATE TABLE IF NOT EXISTS github_activity_events (
    id INT AUTO_INCREMENT PRIMARY KEY,
    workspace_id INT NOT NULL,
    repo_full_name VARCHAR(255) NOT NULL,
    delivery_id VARCHAR(100), -- Webhook-only
    event_type VARCHAR(50) NOT NULL, -- push, pull_request, issues
    action VARCHAR(50), -- opened, closed, merged, etc.
    actor VARCHAR(150),
    entity_type VARCHAR(50), -- commit, pull_request, issue
    entity_id VARCHAR(255),
    branch VARCHAR(255),
    title VARCHAR(500),
    message TEXT,
    commit_count INT,
    html_url VARCHAR(500),
    github_created_at DATETIME,
    payload JSON,
    stored_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_github_events_ws (workspace_id),
    INDEX idx_github_events_repo (repo_full_name),
    UNIQUE KEY uniq_delivery_ws (delivery_id, workspace_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;














UPDATE users
SET is_admin = 1, can_create_workspace = 1
WHERE email = 'your_user_email@example.com';





CREATE TABLE IF NOT EXISTS channels (
  id INT PRIMARY KEY AUTO_INCREMENT,
  workspace_id INT NOT NULL,
  name VARCHAR(255) NOT NULL,
  created_by VARCHAR(255) NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

  UNIQUE KEY uniq_channel (workspace_id, name),
  INDEX idx_channels_ws (workspace_id)
);



CREATE TABLE IF NOT EXISTS channel_members (
  id INT PRIMARY KEY AUTO_INCREMENT,
  channel_id INT NOT NULL,
  user_email VARCHAR(255) NOT NULL,
  added_at DATETIME DEFAULT CURRENT_TIMESTAMP,

  UNIQUE KEY uniq_channel_member (channel_id, user_email),
  INDEX idx_channel_members_channel (channel_id),
  INDEX idx_channel_members_user (user_email)
);





CREATE TABLE IF NOT EXISTS workspace_invites (
  id INT AUTO_INCREMENT PRIMARY KEY,
  workspace_id INT NOT NULL,
  email VARCHAR(255) NOT NULL,
  invited_by VARCHAR(255) NOT NULL,
  status ENUM('pending', 'accepted', 'revoked') DEFAULT 'pending',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

  UNIQUE KEY uniq_invite (workspace_id, email),
  INDEX idx_invite_email (email),

  FOREIGN KEY (workspace_id) REFERENCES workspaces(id)
    ON DELETE CASCADE
);


-- 8) Direct Messages
CREATE TABLE IF NOT EXISTS dm_messages (
    id INT PRIMARY KEY AUTO_INCREMENT,
    workspace_id INT NOT NULL,
    sender_email VARCHAR(255) NOT NULL,
    recipient_email VARCHAR(255) NOT NULL,
    body TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_dm_workspace (workspace_id),
    INDEX idx_dm_sender (sender_email),
    INDEX idx_dm_recipient (recipient_email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 9) Notifications (Consolidated)
CREATE TABLE IF NOT EXISTS notifications (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_email VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL,
    payload JSON NOT NULL,
    is_read TINYINT(1) NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_notifications_user (user_email),
    INDEX idx_notifications_user_unread (user_email, is_read),
    INDEX idx_notifications_type (type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

