-- 一键收藏 · DDL 数据库结构
-- 数据库: yijianshoucang-db (UUID: 1889dceb-8096-4e22-8021-649b7efe0315)
-- 执行方式: CF Dashboard D1 页面手动执行，或通过 wrangler d1 execute

-- users 表（用户）
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    phone TEXT UNIQUE NOT NULL,
    password_hash TEXT,
    nickname TEXT,
    avatar_url TEXT,
    role TEXT DEFAULT 'user',
    status TEXT DEFAULT 'active',
    ban_reason TEXT,
    banned_at TEXT,
    banned_by INTEGER,
    created_at TEXT,
    updated_at TEXT,
    last_login_at TEXT,
    login_count INTEGER DEFAULT 0
);

-- notifications 表（通知）
CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    title TEXT NOT NULL,
    content TEXT,
    is_read INTEGER DEFAULT 0,
    created_at TEXT
);

-- admin_logs 表（管理员操作日志）
CREATE TABLE IF NOT EXISTS admin_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_id INTEGER,
    action TEXT NOT NULL,
    target_user_id INTEGER,
    reason TEXT,
    ip TEXT,
    created_at TEXT
);

-- 创建管理员初始账号
-- 手机号: 13800138000（请尽快修改密码）
-- 角色: admin
INSERT OR IGNORE INTO users (phone, role, status, created_at, updated_at)
VALUES ('13800138000', 'admin', 'active', datetime('now'), datetime('now'));
