#!/bin/bash
# ================================================================
# 文件防篡改系统 - 最终全功能安装脚本 (v2.5 Strict Log)
# 适用于: CentOS 7/8/9 + 宝塔面板 (或其他标准环境)
# ================================================================

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 安装配置
INSTALL_DIR="/www/server/tamper_protect"
LOG_DIR="/www/server/tamper_protect/logs"
DATA_DIR="/www/server/tamper_protect/data"
WEB_PORT=18888

echo -e "${GREEN}"
echo "=============================================="
echo "      文件防篡改系统 - 精简日志版 v2.5"
echo "      (仅记录受保护文件的变动)"
echo "=============================================="
echo -e "${NC}"

# 1. 检查Root权限
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}请使用root用户运行此脚本${NC}"
    exit 1
fi

# 2. 设置系统时区 (北京时间)
ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime 2>/dev/null || true

# 3. 创建目录结构
mkdir -p ${INSTALL_DIR}/templates
mkdir -p ${INSTALL_DIR}/static
mkdir -p ${LOG_DIR}
mkdir -p ${DATA_DIR}

# 4. 安装系统依赖
if command -v yum &> /dev/null; then
    yum install -y python3 python3-pip python3-devel gcc epel-release e2fsprogs 2>/dev/null || true
elif command -v apt &> /dev/null; then
    apt-get update && apt-get install -y python3 python3-pip python3-dev gcc e2fsprogs || true
fi

# 5. 安装Python依赖
pip3 install --upgrade pip 2>/dev/null || true
pip3 install flask flask-login watchdog psutil pyotp qrcode 2>/dev/null || true

# 6. 创建主程序 (main.py) - v2.5 核心逻辑修改
echo -e "${BLUE}[1/3] 更新核心程序逻辑...${NC}"

cat > ${INSTALL_DIR}/main.py << 'MAINPY'
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import time
import sqlite3
import threading
import subprocess
import logging
import pyotp
import qrcode
import io
import base64
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from functools import wraps

# --- 配置路径 ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
LOG_DIR = os.path.join(BASE_DIR, 'logs')
DB_PATH = os.path.join(DATA_DIR, 'tamper_protect.db')
CONFIG_PATH = os.path.join(DATA_DIR, 'config.json')

# --- 系统运行日志 ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler(os.path.join(LOG_DIR, 'tamper_protect.log'), maxBytes=10*1024*1024, backupCount=5),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder=os.path.join(BASE_DIR, 'templates'), static_folder=os.path.join(BASE_DIR, 'static'))
app.secret_key = os.urandom(24).hex()

# --- 工具函数 ---

def get_bj_time():
    utc_now = datetime.utcnow()
    bj_now = utc_now + timedelta(hours=8)
    return bj_now.strftime('%Y-%m-%d %H:%M:%S')

def run_command(cmd):
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        o, e = p.communicate(timeout=30)
        return p.returncode == 0, o.decode(errors='ignore'), e.decode(errors='ignore')
    except Exception as e:
        return False, '', str(e)

def get_file_attr(path):
    if not os.path.exists(path): return False
    ok, out, _ = run_command(['lsattr', '-d', path])
    if ok:
        flags = out.split()[0]
        return 'i' in flags
    return False

# --- 数据库管理 ---

class Database:
    def __init__(self, db_path):
        self.db_path = db_path
        self.lock = threading.Lock()
        self.init_db()
    
    def get_conn(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn
    
    def init_db(self):
        conn = self.get_conn()
        cursor = conn.cursor()
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS protected_dirs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            path TEXT UNIQUE NOT NULL,
            enabled INTEGER DEFAULT 1,
            create_time TIMESTAMP,
            total_count INTEGER DEFAULT 0
        )''')
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS whitelist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            path TEXT UNIQUE NOT NULL,
            type TEXT,
            create_time TIMESTAMP
        )''')
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS protection_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT,
            action_type TEXT,
            is_dir INTEGER DEFAULT 0,
            blocked INTEGER DEFAULT 1,
            create_time TIMESTAMP
        )''')
        
        try: cursor.execute("SELECT is_dir FROM protection_logs LIMIT 1")
        except: 
            try: cursor.execute("ALTER TABLE protection_logs ADD COLUMN is_dir INTEGER DEFAULT 0")
            except: pass

        cursor.execute('''CREATE TABLE IF NOT EXISTS statistics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            stat_date DATE DEFAULT CURRENT_DATE,
            total_events INTEGER DEFAULT 0,
            blocked_events INTEGER DEFAULT 0
        )''')
        
        conn.commit()
        conn.close()

    def execute(self, sql, params=()):
        with self.lock:
            conn = self.get_conn()
            try:
                cursor = conn.cursor()
                cursor.execute(sql, params)
                conn.commit()
                return cursor.lastrowid
            finally:
                conn.close()
    
    def query(self, sql, params=()):
        with self.lock:
            conn = self.get_conn()
            try:
                cursor = conn.cursor()
                cursor.execute(sql, params)
                return [dict(row) for row in cursor.fetchall()]
            finally:
                conn.close()

    def query_one(self, sql, params=()):
        res = self.query(sql, params)
        return res[0] if res else None

db = Database(DB_PATH)

# --- 配置管理 ---

class ConfigManager:
    DEFAULT_CONFIG = {
        "global_enabled": True,
        "protected_extensions": [".php", ".html", ".js", ".css", ".jsp", ".py", ".sh"],
        "whitelist_extensions": [".log", ".txt", ".tmp", ".cache"],
        "admin_password": "admin123",
        "totp_secret": "",
        "totp_enabled": False,
        "log_retention_days": 7
    }
    
    def __init__(self, config_path):
        self.config_path = config_path
        self.config = self.load_config()
    
    def load_config(self):
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    c = json.load(f)
                    for k, v in self.DEFAULT_CONFIG.items():
                        if k not in c: c[k] = v
                    return c
            except: return self.DEFAULT_CONFIG.copy()
        return self.DEFAULT_CONFIG.copy()
    
    def save_config(self):
        with open(self.config_path, 'w', encoding='utf-8') as f:
            json.dump(self.config, f, indent=4)

    def get(self, key, default=None):
        return self.config.get(key, default)

    def set(self, key, value):
        self.config[key] = value
        self.save_config()

config_manager = ConfigManager(CONFIG_PATH)

# --- 核心防护逻辑 ---

class RealTimeHandler(FileSystemEventHandler):
    def on_any_event(self, event):
        # 1. 过滤掉目录的 Modified 事件 (太频繁且无意义)
        if event.is_directory and event.event_type == 'modified':
            return
            
        filepath = event.src_path
        
        # 2. 映射操作类型，只关心这四种
        action_map = { 'created': '新建', 'modified': '修改', 'deleted': '删除', 'moved': '重命名' }
        action_cn = action_map.get(event.event_type)
        if not action_cn: return 

        # 3. 【核心修改】检查是否在白名单DB中 (手动解锁的文件)
        # 如果路径在 whitelist 表中，或者父目录在 whitelist 表中 -> 它是被允许修改的 -> 不记录日志
        is_whitelisted_path = False
        whitelist_items = db.query("SELECT path FROM whitelist")
        for item in whitelist_items:
            if filepath == item['path'] or filepath.startswith(item['path'] + '/'):
                is_whitelisted_path = True
                break
        
        if is_whitelisted_path:
            return # 白名单/解锁文件操作，直接忽略，不记录

        # 4. 【核心修改】检查是否为受保护的后缀
        # 仅针对文件进行后缀检查。如果是目录，默认视为需要保护（除非上面被白名单排除了）
        if not event.is_directory:
            ext = os.path.splitext(filepath)[1].lower()
            protected_exts = config_manager.get('protected_extensions', [])
            # 如果后缀 不在 受保护列表中 -> 忽略，不记录
            if ext not in protected_exts:
                return

        # --- 只有到达这里的事件才会被记录 ---
        # 意味着：文件未被解锁 且 后缀属于受保护列表 (或它是未解锁的目录)
        
        logger.warning(f"TAMPER DETECTED: {action_cn} {filepath}")
        
        # 记录日志 (blocked=1 代表这是受保护文件发生的变动)
        db.execute(
            "INSERT INTO protection_logs (file_path, action_type, is_dir, blocked, create_time) VALUES (?, ?, ?, 1, ?)",
            (filepath, action_cn, 1 if event.is_directory else 0, get_bj_time())
        )
        
        # 统计
        today = datetime.utcnow().strftime('%Y-%m-%d')
        exist = db.query_one("SELECT id FROM statistics WHERE stat_date=?", (today,))
        if exist:
            db.execute("UPDATE statistics SET total_events=total_events+1, blocked_events=blocked_events+1 WHERE id=?", (exist['id'],))
        else:
            db.execute("INSERT INTO statistics (stat_date, total_events, blocked_events) VALUES (?, 1, 1)", (today,))

class SecurityManager:
    def __init__(self):
        self.observer = None
        self.watching = False
    
    def start_monitor(self):
        if self.watching: self.stop_monitor()
        self.observer = Observer()
        handler = RealTimeHandler()
        
        dirs = db.query("SELECT path FROM protected_dirs WHERE enabled=1")
        count = 0
        for d in dirs:
            if os.path.exists(d['path']):
                self.observer.schedule(handler, d['path'], recursive=True)
                count += 1
        
        if count > 0:
            self.observer.start()
            self.watching = True
            logger.info("实时监控已启动")
            
    def stop_monitor(self):
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.observer = None
        self.watching = False

    def clean_old_logs(self):
        days = int(config_manager.get('log_retention_days', 7))
        if days <= 0: days = 7
        utc_now = datetime.utcnow()
        bj_now = utc_now + timedelta(hours=8)
        limit_date = (bj_now - timedelta(days=days)).strftime('%Y-%m-%d %H:%M:%S')
        db.execute("DELETE FROM protection_logs WHERE create_time < ?", (limit_date,))
        logger.info(f"自动清理了 {limit_date} 之前的日志")

    def _set_attr(self, path, lock):
        cmd = ['chattr', '+i' if lock else '-i', path]
        run_command(cmd)

    def apply_policy_recursive(self, dir_path):
        protected_exts = config_manager.get('protected_extensions', [])
        
        self._set_attr(dir_path, True)
        db.execute("DELETE FROM whitelist WHERE path = ?", (dir_path,))

        for root, dirs, files in os.walk(dir_path):
            for d in dirs:
                dpath = os.path.join(root, d)
                self._set_attr(dpath, True)
                db.execute("DELETE FROM whitelist WHERE path = ?", (dpath,))
            for f in files:
                fpath = os.path.join(root, f)
                ext = os.path.splitext(f)[1].lower()
                if ext in protected_exts:
                    self._set_attr(fpath, True)
                    db.execute("DELETE FROM whitelist WHERE path = ?", (fpath,))
                else:
                    self._set_attr(fpath, False)

    def toggle_lock(self, path, lock):
        is_dir = os.path.isdir(path)
        if is_dir:
            if lock:
                db.execute("DELETE FROM whitelist WHERE path = ?", (path,))
                db.execute("DELETE FROM whitelist WHERE path LIKE ?", (path + '/%',))
                threading.Thread(target=self.apply_policy_recursive, args=(path,), daemon=True).start()
                return True, "正在后台应用锁定策略..."
            else:
                db.execute("INSERT INTO whitelist (path, type, create_time) VALUES (?, ?, ?)", 
                          (path, 'dir', get_bj_time()))
                cmd = ['chattr', '-R', '-i', path]
                ok, _, err = run_command(cmd)
                if not ok: return False, f"解锁失败: {err}"
                return True, "目录已递归解锁"
        else:
            if lock:
                db.execute("DELETE FROM whitelist WHERE path = ?", (path,))
            else:
                try: db.execute("INSERT INTO whitelist (path, type, create_time) VALUES (?, ?, ?)", (path, 'file', get_bj_time()))
                except: pass
            self._set_attr(path, lock)
            return True, "操作成功"

security = SecurityManager()

# --- Web 路由 ---

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session: return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password = request.form.get('password')
        code = request.form.get('code')
        if password != config_manager.get('admin_password'):
            return render_template('login.html', error="密码错误")
        if config_manager.get('totp_enabled'):
            totp = pyotp.TOTP(config_manager.get('totp_secret'))
            if not totp.verify(code):
                return render_template('login.html', error="两步验证码错误")
        session['logged_in'] = True
        if not config_manager.get('totp_enabled'): return redirect(url_for('setup_2fa'))
        return redirect(url_for('index'))
    return render_template('login.html', totp_enabled=config_manager.get('totp_enabled'))

@app.route('/setup_2fa')
def setup_2fa():
    if not session.get('logged_in'): return redirect(url_for('login'))
    if config_manager.get('totp_enabled'): return redirect(url_for('index'))
    secret = pyotp.random_base32()
    config_manager.set('totp_secret', secret)
    totp = pyotp.TOTP(secret)
    img = qrcode.make(totp.provisioning_uri(name="TamperProtect", issuer_name="Server"))
    buf = io.BytesIO()
    img.save(buf)
    return render_template('setup_2fa.html', secret=secret, qr_code=base64.b64encode(buf.getvalue()).decode())

@app.route('/verify_2fa', methods=['POST'])
def verify_2fa():
    code = request.json.get('code')
    if pyotp.TOTP(config_manager.get('totp_secret')).verify(code):
        config_manager.set('totp_enabled', True)
        return jsonify({'code': 0, 'msg': '验证成功'})
    return jsonify({'code': 1, 'msg': '验证码错误'})

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template('index.html')

# --- API ---

@app.route('/api/browser', methods=['POST'])
@login_required
def browser():
    path = request.json.get('path', '')
    if not path or not os.path.exists(path): return jsonify({'code': 1, 'msg': '路径不存在'})
    if not os.path.isdir(path): return jsonify({'code': 1, 'msg': '不是目录'})
        
    items = []
    try:
        with os.scandir(path) as it:
            for entry in it:
                is_locked = get_file_attr(entry.path)
                wl = db.query_one("SELECT id FROM whitelist WHERE path=?", (entry.path,))
                status = 'locked' if is_locked else 'unlocked'
                items.append({
                    'name': entry.name,
                    'path': entry.path,
                    'is_dir': entry.is_dir(),
                    'status': status,
                    'whitelisted': True if wl else False
                })
    except Exception as e: return jsonify({'code': 1, 'msg': str(e)})
        
    items.sort(key=lambda x: (not x['is_dir'], x['name']))
    return jsonify({'code': 0, 'data': items, 'current': path})

@app.route('/api/toggle_lock', methods=['POST'])
@login_required
def api_toggle_lock():
    path = request.json.get('path')
    lock = request.json.get('lock')
    if not path or not os.path.exists(path): return jsonify({'code': 1, 'msg': '文件不存在'})
    ok, msg = security.toggle_lock(path, lock)
    return jsonify({'code': 0 if ok else 1, 'msg': msg})

@app.route('/api/logs', methods=['GET', 'DELETE'])
@login_required
def handle_logs():
    if request.method == 'DELETE':
        db.execute("DELETE FROM protection_logs")
        return jsonify({'code': 0, 'msg': '日志已清空'})
    page = int(request.args.get('page', 1))
    limit = int(request.args.get('limit', 20))
    offset = (page-1)*limit
    
    logs = db.query("SELECT * FROM protection_logs ORDER BY create_time DESC LIMIT ? OFFSET ?", (limit, offset))
    total = db.query_one("SELECT COUNT(*) as c FROM protection_logs")['c']
    return jsonify({'code': 0, 'data': logs, 'total': total})

@app.route('/api/config', methods=['GET', 'POST'])
@login_required
def handle_config():
    if request.method == 'POST':
        data = request.json
        config_manager.set('protected_extensions', data.get('protected_extensions', []))
        config_manager.set('whitelist_extensions', data.get('whitelist_extensions', []))
        config_manager.set('log_retention_days', int(data.get('log_retention_days', 7)))
        
        def refresh_policy():
            dirs = db.query("SELECT path FROM protected_dirs WHERE enabled=1")
            for d in dirs:
                if os.path.exists(d['path']):
                    security.apply_policy_recursive(d['path'])
        threading.Thread(target=refresh_policy, daemon=True).start()
        
        return jsonify({'code': 0, 'msg': '配置已保存'})
    return jsonify({'code': 0, 'data': config_manager.config})

@app.route('/api/dirs', methods=['GET', 'POST', 'DELETE'])
@login_required
def handle_dirs():
    if request.method == 'POST':
        path = request.json.get('path')
        if not os.path.isdir(path): return jsonify({'code': 1, 'msg': '目录不存在'})
        try:
            db.execute("INSERT INTO protected_dirs (path, create_time) VALUES (?, ?)", (path, get_bj_time()))
            threading.Thread(target=security.apply_policy_recursive, args=(path,), daemon=True).start()
            security.start_monitor()
            return jsonify({'code': 0, 'msg': '添加成功'})
        except Exception as e: return jsonify({'code': 1, 'msg': f'失败: {str(e)}'})
        
    if request.method == 'DELETE':
        id = request.args.get('id')
        dir_info = db.query_one("SELECT path FROM protected_dirs WHERE id=?", (id,))
        if dir_info: security.toggle_lock(dir_info['path'], False)
        db.execute("DELETE FROM protected_dirs WHERE id=?", (id,))
        security.start_monitor()
        return jsonify({'code': 0, 'msg': '删除成功'})
        
    data = db.query("SELECT * FROM protected_dirs")
    result = []
    for d in data:
        is_locked = get_file_attr(d['path'])
        d['status_text'] = '已锁定' if is_locked else '未锁定'
        result.append(d)
    return jsonify({'code': 0, 'data': result})

def scheduled_tasks():
    while True:
        try: security.clean_old_logs()
        except: pass
        time.sleep(3600 * 24)

if __name__ == '__main__':
    if config_manager.get('global_enabled'): security.start_monitor()
    threading.Thread(target=scheduled_tasks, daemon=True).start()
    app.run(host='0.0.0.0', port=18888, threaded=True)
MAINPY

# 7. 写入 HTML 模板 (Login, 2FA, Index)
echo -e "${BLUE}[2/3] 更新前端页面...${NC}"

# Login HTML
cat > ${INSTALL_DIR}/templates/login.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>系统登录 - 文件防篡改</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { background: #f0f2f5; display: flex; justify-content: center; align-items: center; height: 100vh; font-family: sans-serif; }
        .box { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); width: 100%; max-width: 360px; }
        input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        button { width: 100%; padding: 10px; background: #1890ff; color: white; border: none; border-radius: 4px; cursor: pointer; }
        .error { color: red; font-size: 12px; margin-bottom: 10px; }
    </style>
</head>
<body>
    <div class="box">
        <h2 style="text-align:center">文件防篡改系统</h2>
        {% if error %}<div class="error">{{ error }}</div>{% endif %}
        <form method="POST">
            <input type="password" name="password" placeholder="管理员密码" required>
            {% if totp_enabled %}
            <input type="text" name="code" placeholder="Google 验证码 (6位)" required autocomplete="off">
            {% endif %}
            <button type="submit">登 录</button>
        </form>
    </div>
</body>
</html>
EOF

# Setup 2FA HTML
cat > ${INSTALL_DIR}/templates/setup_2fa.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>绑定 2FA</title>
    <style>
        body { background: #f0f2f5; display: flex; justify-content: center; align-items: center; height: 100vh; font-family: sans-serif; }
        .box { background: white; padding: 30px; border-radius: 8px; text-align: center; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
        input { padding: 8px; width: 150px; text-align: center; }
        button { padding: 8px 15px; background: #1890ff; color: white; border: none; cursor: pointer; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="box">
        <h2>首次登录安全设置</h2>
        <img src="data:image/png;base64,{{ qr_code }}" style="width:200px;height:200px">
        <p style="font-family:monospace;background:#eee;padding:5px">{{ secret }}</p>
        <div>
            <input type="text" id="code" placeholder="输入6位验证码">
            <button onclick="verify()">验证并开启</button>
        </div>
    </div>
    <script>
        function verify() {
            const code = document.getElementById('code').value;
            fetch('/verify_2fa', {
                method: 'POST', headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({code})
            }).then(r=>r.json()).then(res=>{
                if(res.code===0) window.location.href='/';
                else alert(res.msg);
            })
        }
    </script>
</body>
</html>
EOF

# Index HTML
cat > ${INSTALL_DIR}/templates/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>文件防篡改系统 v2.5</title>
    <link href="https://cdn.bootcdn.net/ajax/libs/font-awesome/5.15.3/css/all.min.css" rel="stylesheet">
    <style>
        body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; background: #f0f2f5; }
        .header { background: #001529; color: white; padding: 0 20px; height: 64px; display: flex; align-items: center; justify-content: space-between; }
        .main { display: flex; min-height: calc(100vh - 64px); }
        .sidebar { width: 220px; background: white; border-right: 1px solid #eee; }
        .content { flex: 1; padding: 24px; }
        .menu-item { padding: 15px 24px; cursor: pointer; color: #333; transition: all .3s; display: flex; align-items: center; gap: 10px; }
        .menu-item:hover, .menu-item.active { background: #e6f7ff; color: #1890ff; border-right: 3px solid #1890ff; }
        .card { background: white; padding: 24px; border-radius: 4px; margin-bottom: 24px; }
        .page { display: none; }
        .page.active { display: block; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px 0; border-bottom: 1px solid #f0f0f0; text-align: left; }
        th { background: #fafafa; padding-left: 10px; }
        td { padding-left: 10px; }
        .btn { padding: 5px 12px; border: none; border-radius: 4px; cursor: pointer; color: white; font-size: 13px; margin-right: 5px; }
        .btn-blue { background: #1890ff; }
        .btn-red { background: #ff4d4f; }
        .btn-green { background: #52c41a; }
        .tag { padding: 2px 8px; border-radius: 4px; font-size: 12px; }
        .tag-lock { background: #fff1f0; color: #f5222d; border: 1px solid #ffa39e; }
        .tag-unlock { background: #f6ffed; color: #52c41a; border: 1px solid #b7eb8f; }
        .tag-dir { background: #e6f7ff; color: #1890ff; border: 1px solid #91d5ff; }
        .breadcrumb { padding: 10px 0; color: #666; font-size: 14px; }
        .breadcrumb span { cursor: pointer; color: #1890ff; }
        .browser-item { display: flex; align-items: center; padding: 10px; border-bottom: 1px solid #f0f0f0; }
        .browser-item:hover { background: #fafafa; }
        .item-icon { width: 30px; text-align: center; color: #ffec3d; font-size: 18px; }
        .item-icon.file { color: #8c8c8c; }
        .item-name { flex: 1; cursor: pointer; }
        .item-status { width: 100px; text-align: center; }
        .item-action { width: 100px; text-align: right; }
        input[type="text"], input[type="number"] { padding: 6px; border: 1px solid #d9d9d9; border-radius: 4px; width: 200px; }
    </style>
</head>
<body>
    <div class="header">
        <h2><i class="fas fa-shield-alt"></i> 文件防篡改系统 v2.5</h2>
        <a href="/logout" style="color:white;text-decoration:none">退出</a>
    </div>
    <div class="main">
        <div class="sidebar">
            <div class="menu-item active" onclick="showPage('status')"><i class="fas fa-chart-line"></i> 运行状态</div>
            <div class="menu-item" onclick="showPage('browser')"><i class="fas fa-folder-open"></i> 文件审计</div>
            <div class="menu-item" onclick="showPage('logs')"><i class="fas fa-history"></i> 日志审计</div>
            <div class="menu-item" onclick="showPage('config')"><i class="fas fa-cog"></i> 系统配置</div>
        </div>
        <div class="content">
            <!-- 状态页 -->
            <div id="page-status" class="page active">
                <div class="card">
                    <h3>保护目录管理</h3>
                    <div style="margin-bottom:15px">
                        <input type="text" id="new-dir" placeholder="/www/wwwroot/example.com">
                        <button class="btn btn-blue" onclick="addDir()">添加目录并应用策略</button>
                    </div>
                    <table id="dir-table">
                        <thead><tr><th>路径</th><th>锁定状态</th><th>添加时间 (北京)</th><th>操作</th></tr></thead>
                        <tbody></tbody>
                    </table>
                </div>
            </div>
            
            <!-- 浏览器页 -->
            <div id="page-browser" class="page">
                <div class="card">
                    <h3>文件审计与控制</h3>
                    <div class="breadcrumb" id="browser-path"></div>
                    <div id="browser-list"></div>
                </div>
            </div>
            
            <!-- 日志页 -->
            <div id="page-logs" class="page">
                <div class="card">
                    <div style="display:flex;justify-content:space-between;align-items:center">
                        <h3>异常变动记录 (仅受保护文件)</h3>
                        <div>
                            <button class="btn btn-red" onclick="clearLogs()">清空日志</button>
                            <button class="btn btn-blue" onclick="loadLogs(1)">刷新</button>
                        </div>
                    </div>
                    <table id="log-table">
                        <thead><tr><th>时间 (北京)</th><th>类型</th><th>路径</th><th>操作</th><th>性质</th></tr></thead>
                        <tbody></tbody>
                    </table>
                </div>
            </div>
            
            <!-- 配置页 -->
            <div id="page-config" class="page">
                <div class="card">
                    <h3>系统配置</h3>
                    <p>受保护文件后缀 (逗号分隔):</p><input type="text" id="cfg-exts" style="width:100%">
                    <p style="font-size:12px;color:#999">注意：只有此列表内的文件后缀被修改时，才会触发日志记录。</p>
                    <p>白名单后缀 (逗号分隔):</p><input type="text" id="cfg-wl" style="width:100%">
                    <h3>清理策略</h3>
                    <p>日志保留天数:</p><input type="number" id="cfg-days">
                    <br><br><button class="btn btn-blue" onclick="saveConfig()">保存配置</button>
                </div>
            </div>
        </div>
    </div>
    <script>
        function showPage(id) {
            document.querySelectorAll('.page').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.menu-item').forEach(el => el.classList.remove('active'));
            document.getElementById('page-'+id).classList.add('active');
            event.currentTarget.classList.add('active');
            if(id === 'status') loadDirs();
            if(id === 'browser') loadBrowser(currentPath || '/www');
            if(id === 'logs') loadLogs();
            if(id === 'config') loadConfig();
        }
        
        function loadDirs() {
            fetch('/api/dirs').then(r=>r.json()).then(res => {
                const html = res.data.map(d => `
                    <tr>
                        <td>${d.path}</td>
                        <td><span class="tag ${d.status_text=='已锁定'?'tag-lock':'tag-unlock'}">${d.status_text}</span></td>
                        <td>${d.create_time||'-'}</td>
                        <td><button class="btn btn-red" onclick="delDir(${d.id})">删除</button>
                            <button class="btn btn-blue" onclick="showPage('browser');loadBrowser('${d.path}')">文件管理</button>
                        </td>
                    </tr>
                `).join('');
                document.querySelector('#dir-table tbody').innerHTML = html;
            });
        }
        function addDir() {
            const path = document.getElementById('new-dir').value;
            fetch('/api/dirs', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({path})})
            .then(r=>r.json()).then(res=>{ alert(res.msg); loadDirs(); });
        }
        function delDir(id) {
            if(confirm('确定停止保护并删除吗？')) fetch('/api/dirs?id='+id, {method:'DELETE'}).then(r=>r.json()).then(res=>{loadDirs()});
        }
        
        let currentPath = '';
        function loadBrowser(path) {
            fetch('/api/browser', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({path})})
            .then(r=>r.json()).then(res => {
                if(res.code !== 0) { alert(res.msg); return; }
                currentPath = res.current;
                const parts = currentPath.split('/').filter(p=>p);
                let crumbHtml = '<span onclick="loadBrowser(\'/\')">/</span>';
                let acc = '';
                parts.forEach(p => { acc += '/' + p; crumbHtml += ` / <span onclick="loadBrowser('${acc}')">${p}</span>`; });
                document.getElementById('browser-path').innerHTML = crumbHtml;
                
                const listHtml = res.data.map(item => {
                    const icon = item.is_dir ? '<i class="fas fa-folder"></i>' : '<i class="fas fa-file-alt item-icon file"></i>';
                    const iconClass = item.is_dir ? '' : 'file';
                    const statusTag = item.status === 'locked' 
                        ? '<span class="tag tag-lock"><i class="fas fa-lock"></i> 锁定</span>' 
                        : '<span class="tag tag-unlock"><i class="fas fa-lock-open"></i> 未锁</span>';
                    const btn = item.status === 'locked'
                        ? `<button class="btn btn-green" onclick="toggleLock('${item.path}', false)">解锁</button>`
                        : `<button class="btn btn-red" onclick="toggleLock('${item.path}', true)">锁定</button>`;
                    return `<div class="browser-item">
                        <div class="item-icon ${iconClass}">${icon}</div>
                        <div class="item-name" onclick="${item.is_dir ? `loadBrowser('${item.path}')` : ''}">${item.name}</div>
                        <div class="item-status">${statusTag}</div>
                        <div class="item-action">${btn}</div>
                    </div>`;
                }).join('');
                document.getElementById('browser-list').innerHTML = listHtml;
            });
        }
        function toggleLock(path, lock) {
            if(!confirm(`确定要${lock?'锁定':'解锁'}吗？`)) return;
            fetch('/api/toggle_lock', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({path, lock})})
            .then(r=>r.json()).then(res => { if(res.code === 0) loadBrowser(currentPath); else alert(res.msg); });
        }
        
        function loadLogs(page=1) {
            fetch(`/api/logs?page=${page}`).then(r=>r.json()).then(res => {
                if(!res.data) return;
                const html = res.data.map(l => {
                    const typeTag = l.is_dir 
                        ? '<span class="tag tag-dir">文件夹</span>' 
                        : '<span class="tag" style="background:#f0f0f0">文件</span>';
                    return `
                    <tr><td>${l.create_time}</td>
                        <td>${typeTag}</td>
                        <td style="font-size:12px;color:#666;word-break:break-all">${l.file_path}</td>
                        <td style="font-weight:bold">${l.action_type}</td>
                        <td><span style="color:red;font-weight:bold">违规变动</span></td>
                    </tr>
                `}).join('');
                document.querySelector('#log-table tbody').innerHTML = html;
            });
        }
        function clearLogs() {
            if(!confirm('确定要清空所有日志吗？')) return;
            fetch('/api/logs', {method:'DELETE'}).then(r=>r.json()).then(res=>{ alert(res.msg); loadLogs(); });
        }
        
        function loadConfig() {
            fetch('/api/config').then(r=>r.json()).then(res => {
                document.getElementById('cfg-exts').value = res.data.protected_extensions.join(',');
                document.getElementById('cfg-wl').value = res.data.whitelist_extensions.join(',');
                document.getElementById('cfg-days').value = res.data.log_retention_days;
            });
        }
        function saveConfig() {
            const data = {
                protected_extensions: document.getElementById('cfg-exts').value.split(',').filter(x=>x),
                whitelist_extensions: document.getElementById('cfg-wl').value.split(',').filter(x=>x),
                log_retention_days: document.getElementById('cfg-days').value
            };
            fetch('/api/config', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(data)})
            .then(r=>r.json()).then(res => alert(res.msg));
        }
        
        loadDirs();
    </script>
</body>
</html>
EOF

# 8. 创建 systemd 服务
echo -e "${BLUE}[3/3] 配置并启动服务...${NC}"
cat > /etc/systemd/system/tamper-protect.service << EOF
[Unit]
Description=File Tamper Protection System
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=/usr/bin/python3 ${INSTALL_DIR}/main.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

chmod +x ${INSTALL_DIR}/main.py
chmod -R 755 ${INSTALL_DIR}

systemctl daemon-reload
systemctl enable tamper-protect
systemctl restart tamper-protect

SERVER_IP=$(hostname -I | awk '{print $1}')

echo ""
echo -e "${GREEN}=============================================="
echo "      文件防篡改系统 v2.5 安装成功！"
echo "=============================================="
echo -e "${NC}"
echo -e "访问地址: ${GREEN}http://${SERVER_IP}:${WEB_PORT}${NC}"
echo -e "默认密码: ${YELLOW}admin123${NC}"
echo ""
