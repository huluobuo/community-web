from flask import Flask, render_template, request, redirect, url_for, jsonify, send_from_directory, session, flash
from datetime import datetime, timedelta
import json
import os
import humanize
import mimetypes
import hashlib
import time
import base64
from collections import defaultdict
from functools import wraps
from dotenv import load_dotenv

# 用于AES解密
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# 首先将用户名和密码转换为UTF-8编码的字符串
# 模拟前端的TextEncoder/TextDecoder行为
def encode_decode_utf8(s):
    # 在Python中，字符串默认就是Unicode，所以我们需要先编码成UTF-8字节，再解码回字符串
    # 这样可以确保与前端的TextEncoder/TextDecoder行为一致
    return s.encode('utf-8').decode('utf-8')

# 加载.env文件中的环境变量
load_dotenv()

# 设置上传文件夹和最大文件大小
UPLOAD_FOLDER = 'uploads'
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB

# os.system('start http://127.0.0.1:8000')

app = Flask(__name__, template_folder='static/html')

# 存储留言的列表
messages = []

# 生成密码哈希
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'fallback-secret-key')  # 从环境变量获取密钥，如不存在则使用默认值

# 密码哈希函数
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# 验证密码
def verify_password(stored_hash, password):
    return stored_hash == hash_password(password)

# 解密客户端加密的密码
# 新的解密函数，支持用户名+密码的组合密钥
# 客户端现在使用TextEncoder/TextDecoder来确保UTF-8编码
# 然后使用用户名+密码的组合作为密钥来加密密码
# 这个函数需要相应地调整以处理新的加密方式

def decrypt_password(encrypted_password, password):
    try:
        # 解析加密数据
        encrypted_data = base64.b64decode(encrypted_password)
        
        # 从加密数据中提取盐和密文
        salt = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        # 从密码和盐生成密钥和IV
        key = hashlib.sha256(password.encode() + salt).digest()
        iv = hashlib.md5(password.encode() + salt).digest()
        
        # 创建AES解密器并解密
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
        
        return decrypted.decode('utf-8')
    except Exception as e:
        # 如果解密失败，返回原始密码（这是一个回退机制）
        print(f"解密失败: {str(e)}")
        return password

# 由于客户端使用CryptoJS的AES加密，我们需要一个兼容的解密函数
# 现在更新这个函数以支持用户名+密码的组合密钥

def decrypt_cryptojs_aes(encrypted_str, password):
    try:
        # 解析CryptoJS格式的加密数据
        # 格式为: Salted__<salt><ciphertext>
        encrypted_data = base64.b64decode(encrypted_str)
        
        # 检查是否是Salted__格式
        if encrypted_data[:8] != b'Salted__':
            raise ValueError("不是有效的CryptoJS AES加密数据")
        
        # 提取盐和密文
        salt = encrypted_data[8:16]
        ciphertext = encrypted_data[16:]
        
        # 使用OpenSSL密钥派生函数从密码和盐生成密钥和IV
        # 这是CryptoJS默认的密钥派生方式
        key_iv = hashlib.md5(password.encode() + salt).digest()
        key = key_iv
        iv = hashlib.md5(key + password.encode() + salt).digest()
        
        # 创建AES解密器并解密
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
        
        return decrypted.decode('utf-8')
    except Exception as e:
        # 如果解密失败，返回原始密码（这是一个回退机制）
        print(f"解密失败: {str(e)}")
        return password

# 直接从users.json文件读取用户数据
def get_users():
    if os.path.exists('users.json'):
        try:
            with open('users.json', 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {}
    return {}

# 确保至少有一个管理员用户并获取用户数据
def get_safe_users():
    users = get_users()
    
    # 确保至少有一个管理员用户
    if 'admin' not in users:
        # 从环境变量获取默认管理员密码和邮箱
        default_admin_password = os.getenv('DEFAULT_ADMIN_PASSWORD', 'admin123')
        admin_email = os.getenv('ADMIN_EMAIL', 'admin@example.com')
        users['admin'] = {
            'email': admin_email,
            'password': hash_password(default_admin_password),  # 使用环境变量中的密码
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'is_admin': True
        }
        save_users(users)
    
    return users

# 保存用户数据
def save_users(users_data):
    with open('users.json', 'w', encoding='utf-8') as f:
        json.dump(users_data, f, ensure_ascii=False, indent=2)

# 确保数据持久化
def load_messages():
    global messages
    if os.path.exists('messages.json'):
        with open('messages.json', 'r', encoding='utf-8') as f:
            messages = json.load(f)

def save_messages():
    with open('messages.json', 'w', encoding='utf-8') as f:
        json.dump(messages, f, ensure_ascii=False, indent=2)

# 加载现有留言
load_messages()

# 文件上传配置
UPLOAD_FOLDER = 'files'
MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB

# 文件类型分类
FILE_CATEGORIES = {
    '代码': ['py', 'java', 'c', 'cpp', 'js', 'html', 'css', 'php', 'go', 'rb', 'swift', 'kt', 'ts', 'sql'],
    '学习文件': ['txt', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx'],
    '图片': ['png', 'jpg', 'jpeg', 'gif'],
    '音频': ['mp3'],
    '视频': ['mp4'],
    '压缩包': ['zip', 'rar', '7z'],
    '其他': []  # 其他类别将包含不在上述分类中的文件
}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# 存储文件信息的字典
file_metadata = {}

# 用于存储下载请求记录的字典，用于反爬虫
# 格式: {ip: {last_request_time, request_count}}
download_requests = defaultdict(lambda: {'last_request_time': datetime.now(), 'request_count': 0})

# 下载限制配置
MAX_DOWNLOADS_PER_MINUTE = 10  # 每分钟最多下载次数
BLOCKED_USER_AGENTS = ['bot', 'crawler', 'spider', 'scrapy', 'wget', 'curl']  # 阻止的User-Agent关键词

# IP白名单配置
WHITELISTED_IPS = ['127.0.0.1', '::1']  # 默认包含本地IP

# 用户名白名单配置
WHITELISTED_USERNAMES = ['admin']  # 默认包含admin用户

# 蜜罐配置 - 记录访问蜜罐的IP
honeypot_access_log = []

# 确保文件元数据持久化
def load_file_metadata():
    global file_metadata
    if os.path.exists('file_metadata.json'):
        try:
            with open('file_metadata.json', 'r', encoding='utf-8') as f:
                file_metadata = json.load(f)
        except:
            file_metadata = {}

# 保存文件元数据
def save_file_metadata():
    with open('file_metadata.json', 'w', encoding='utf-8') as f:
        json.dump(file_metadata, f, ensure_ascii=False, indent=2)

# 加载现有文件元数据
load_file_metadata()

def allowed_file(filename):
    # 允许所有文件类型，仅检查文件是否有扩展名
    return '.' in filename and filename.rsplit('.', 1)[1].strip() != ''

def secure_filename(filename):
    # 移除不安全的字符
    filename = filename.replace(' ', '_')
    filename = ''.join(c for c in filename if c.isalnum() or c in '._-')
    return filename

def get_file_category(filename):
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    for category, extensions in FILE_CATEGORIES.items():
        if category == '其他':
            continue  # 跳过其他类别，最后返回
        if ext in extensions:
            return category
    return '其他'

def get_file_info(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        stats = os.stat(file_path)
        mime_type, _ = mimetypes.guess_type(filename)
        
        # 获取文件备注
        description = file_metadata.get(filename, {}).get('description', '')
        
        return {
            'name': filename,
            'size': humanize.naturalsize(stats.st_size),
            'time': datetime.fromtimestamp(stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
            'category': get_file_category(filename),
            'mime_type': mime_type or 'application/octet-stream',
            'description': description
        }
    return None

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/message-board')
def message_board():
    return render_template('message_board.html', messages=messages)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/files')
def files():
    category = request.args.get('category', '')
    search = request.args.get('search', '')
    
    files = []
    for filename in os.listdir(app.config['UPLOAD_FOLDER']):
        if os.path.isfile(os.path.join(app.config['UPLOAD_FOLDER'], filename)):
            file_info = get_file_info(filename)
            if file_info:
                if category and file_info['category'] != category:
                    continue
                if search and search.lower() not in filename.lower():
                    continue
                files.append(file_info)
    
    files.sort(key=lambda x: x['time'], reverse=True)
    return render_template('files.html', files=files, categories=FILE_CATEGORIES.keys(), current_category=category)

@app.route('/upload', methods=['POST'])
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': '没有选择文件'}), 400
            
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': '没有选择文件'}), 400
            
        if not allowed_file(file.filename):
            return jsonify({'error': '文件名格式不正确'}), 400
            
        # 获取文件备注
        description = request.form.get('description', '')
            
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # 如果文件已存在，添加时间戳
        if os.path.exists(file_path):
            name, ext = os.path.splitext(filename)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{name}_{timestamp}{ext}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        file.save(file_path)
        
        # 保存文件元数据
        if description:
            file_metadata[filename] = {
                'description': description,
                'upload_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            save_file_metadata()
        
        return jsonify({'success': True, 'filename': filename}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500



@app.route('/download/<filename>')
def download_file(filename):
    # 检查用户是否已登录
    current_user = session.get('username')
    
    # 如果用户未登录，重定向到登录页面
    if not current_user:
        flash('请先登录后再下载文件', 'warning')
        return redirect(url_for('login'))
    
    # 获取客户端IP
    client_ip = request.remote_addr
    
    # 检查用户名是否在白名单中
    if current_user in WHITELISTED_USERNAMES:
        # 白名单用户不受限制
        pass
    elif client_ip in WHITELISTED_IPS:
        # 白名单IP不受限制
        pass
    else:
        # 检查User-Agent
        user_agent = request.headers.get('User-Agent', '').lower()
        for blocked_agent in BLOCKED_USER_AGENTS:
            if blocked_agent in user_agent:
                return "禁止爬虫访问", 403
        
        # 添加延迟，限制下载速度
        time.sleep(1)  # 非白名单用户每次下载延迟1秒
    
    # 检查文件是否存在
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.isfile(file_path):
        return "文件不存在", 404
    
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route('/download-page/<filename>')
def download_page(filename):
    file_info = get_file_info(filename)
    if not file_info:
        return "文件不存在", 404
    return render_template('download.html', file_info=file_info)



@app.route('/add_message', methods=['POST'])
def add_message():
    name = request.form.get('name')
    content = request.form.get('message')
    time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    if name and content:
        messages.append({
            'name': name,
            'content': content,
            'time': time
        })
        save_messages()
    
    return redirect(url_for('message_board'))

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/register', methods=['POST'])
def register_post():
    # 添加详细日志
    app.logger.info('接收到注册请求')
    app.logger.info(f'请求方法: {request.method}')
    app.logger.info(f'表单数据: {request.form}')
    
    # 获取表单数据
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')
    
    # 简单验证
    if not username or not password or not email:
        app.logger.warning('注册失败: 缺少必要字段')
        flash('请填写所有必填字段', 'danger')
        return redirect(url_for('register'))
    
    # 验证密码一致性
    if password != confirm_password:
        app.logger.warning('注册失败: 密码不一致')
        flash('两次输入的密码不一致', 'danger')
        return redirect(url_for('register'))
    
    # 验证密码长度
    if len(password) < 6:
        app.logger.warning('注册失败: 密码长度不足')
        flash('密码长度至少为6位', 'danger')
        return redirect(url_for('register'))
    
    # 获取用户数据
    users = get_safe_users()
    
    # 检查用户名是否已存在
    if username in users:
        app.logger.warning(f'注册失败: 用户名 {username} 已存在')
        flash('该用户名已被注册', 'danger')
        return redirect(url_for('register'))
    
    # 创建新用户
    users[username] = {
        'email': email,
        'password': hash_password(password),
        'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'is_admin': False  # 默认为普通用户
    }
    
    # 保存用户数据
    save_users(users)
    app.logger.info(f'注册成功: 用户 {username} 已创建')
    
    # 重定向到登录页面
    flash('注册成功！请登录', 'success')
    return redirect(url_for('login'))

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login_post():
    input_value = request.form.get('username')
    password = request.form.get('password')
    remember = request.form.get('remember')
    
    # 验证密码是否为空
    if not password:
        flash('密码不能为空', 'danger')
        return redirect(url_for('login'))
    
    # 验证密码长度
    if len(password) < 6:
        flash('密码长度至少为6个字符', 'danger')
        return redirect(url_for('login'))
    
    # 获取用户数据
    users = get_safe_users()
    
    # 查找对应的用户名
    username = None
    
    # 首先检查是否直接是用户名
    if input_value in users:
        username = input_value
    else:
        # 检查是否是电子邮箱
        for user, info in users.items():
            if info.get('email') == input_value:
                username = user
                break
    
    # 检查用户是否存在
    if not username:
        flash('用户名或密码错误', 'danger')
        return redirect(url_for('login'))
    
    # 获取存储的哈希密码
    stored_hash = users[username]['password']
    
    # 直接验证原始密码
    if verify_password(stored_hash, password):
        # 创建用户会话
        session['username'] = username
        session['is_admin'] = users[username]['is_admin']
        
        # 如果用户选择记住我，则设置较长的cookie过期时间
        if remember:
            session.permanent = True
        
        # 登录成功后重定向到首页
        return redirect(url_for('home'))
    
    # 密码验证失败
    flash('用户名或密码错误', 'danger')
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    # 清除会话
    session.pop('username', None)
    
    # 注销成功后重定向到首页
    return redirect(url_for('home'))

@app.route('/more')
def more():
    return render_template('more.html')

@app.route('/static/img/favicon.ico')
def favicon():
    return send_from_directory('static', 'img/favicon.ico')

# Bootstrap CSS 现在通过 CDN 提供

@app.route('/static/css/custom.css')
def custom_css():
    return send_from_directory('static/css', 'custom.css')



# 管理员验证装饰器
def admin_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        # 检查用户是否登录
        if 'username' not in session:
            return redirect(url_for('login'))
        
        # 检查用户是否为管理员
        username = session['username']
        users = get_safe_users()
        if username not in users or not users[username].get('is_admin', False):
            return "权限不足，只有管理员可以访问此页面", 403
        
        return func(*args, **kwargs)
    return decorated_function

# 配置管理权限装饰器 - 只有特定用户可以配置
def config_admin_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        # 首先检查是否是管理员
        if 'username' not in session:
            return redirect(url_for('login'))
        
        username = session['username']
        users = get_safe_users()
        if username not in users or not users[username].get('is_admin', False):
            return "权限不足，只有管理员可以访问此页面", 403
        
        # 限制只有特定的超级管理员可以访问配置管理
        # 目前只允许原始管理员用户访问配置管理
        if username != 'admin':
            return "权限不足，只有超级管理员可以访问配置管理页面", 403
        
        return func(*args, **kwargs)
    return decorated_function

# 配置管理路由
@app.route('/admin/config', methods=['GET', 'POST'])
@config_admin_required
def admin_config():
    if request.method == 'POST':
        try:
            # 读取当前.env文件内容以显示，但不进行修改
            config_dict = {}
            if os.path.exists('.env'):
                try:
                    with open('.env', 'r', encoding='utf-8') as f:
                        for line in f.readlines():
                            if '=' in line and not line.strip().startswith('#'):
                                key, value = line.strip().split('=', 1)
                                config_dict[key] = value
                except:
                    pass
            
            # 处理其他配置
            # 更新全局变量
            if 'MAX_DOWNLOADS_PER_MINUTE' in request.form and request.form['MAX_DOWNLOADS_PER_MINUTE'].strip():
                try:
                    max_downloads = int(request.form['MAX_DOWNLOADS_PER_MINUTE'])
                    app.config['MAX_DOWNLOADS_PER_MINUTE'] = max_downloads
                except ValueError:
                    pass
            
            # 更新阻止的User-Agent
            if 'BLOCKED_USER_AGENTS' in request.form:
                blocked_agents = request.form['BLOCKED_USER_AGENTS'].strip()
                if blocked_agents:
                    app.config['BLOCKED_USER_AGENTS'] = [agent.strip() for agent in blocked_agents.split(',')]
                else:
                    app.config['BLOCKED_USER_AGENTS'] = []
            
            # 更新IP白名单
            if 'WHITELISTED_IPS' in request.form:
                whitelisted_ips = request.form['WHITELISTED_IPS'].strip()
                if whitelisted_ips:
                    app.config['WHITELISTED_IPS'] = [ip.strip() for ip in whitelisted_ips.split(',')]
                else:
                    app.config['WHITELISTED_IPS'] = []
            
            # 更新用户名白名单
            if 'WHITELISTED_USERNAMES' in request.form:
                whitelisted_usernames = request.form['WHITELISTED_USERNAMES'].strip()
                if whitelisted_usernames:
                    app.config['WHITELISTED_USERNAMES'] = [username.strip() for username in whitelisted_usernames.split(',')]
                else:
                    app.config['WHITELISTED_USERNAMES'] = []
            
            # 刷新配置
            load_dotenv()
            
            return render_template('admin_config.html', 
                                 env_config=config_dict, 
                                 max_downloads=app.config.get('MAX_DOWNLOADS_PER_MINUTE', 5), 
                                 blocked_agents=', '.join(app.config.get('BLOCKED_USER_AGENTS', [])),
                                 whitelisted_ips=', '.join(app.config.get('WHITELISTED_IPS', [])),
                                 whitelisted_usernames=', '.join(app.config.get('WHITELISTED_USERNAMES', [])),
                                 success='配置已成功保存！')
            
        except Exception as e:
            # 读取.env文件以获取当前配置
            config_dict = {}
            if os.path.exists('.env'):
                try:
                    with open('.env', 'r', encoding='utf-8') as f:
                        for line in f.readlines():
                            if '=' in line and not line.strip().startswith('#'):
                                key, value = line.strip().split('=', 1)
                                config_dict[key] = value
                except:
                    pass
            
            return render_template('admin_config.html', 
                                 env_config=config_dict, 
                                 max_downloads=app.config.get('MAX_DOWNLOADS_PER_MINUTE', 5), 
                                 blocked_agents=', '.join(app.config.get('BLOCKED_USER_AGENTS', [])),
                                 whitelisted_ips=', '.join(app.config.get('WHITELISTED_IPS', [])),
                                 whitelisted_usernames=', '.join(app.config.get('WHITELISTED_USERNAMES', [])),
                                 error=f'保存配置时出错: {str(e)}')
    else:
        # 读取.env文件以显示当前配置
        config_dict = {}
        if os.path.exists('.env'):
            try:
                with open('.env', 'r', encoding='utf-8') as f:
                    for line in f.readlines():
                        if '=' in line and not line.strip().startswith('#'):
                            key, value = line.strip().split('=', 1)
                            config_dict[key] = value
            except:
                pass
        
        return render_template('admin_config.html', 
                             env_config=config_dict, 
                             max_downloads=app.config.get('MAX_DOWNLOADS_PER_MINUTE', 5), 
                             blocked_agents=', '.join(app.config.get('BLOCKED_USER_AGENTS', [])),
                             whitelisted_ips=', '.join(app.config.get('WHITELISTED_IPS', [])),
                             whitelisted_usernames=', '.join(app.config.get('WHITELISTED_USERNAMES', [])))

# 管理员页面路由
@app.route('/admin')
@admin_required
def admin_panel():
    # 获取用户数据
    users = get_safe_users()
    
    # 获取系统信息
    user_count = len(users)
    message_count = len(messages)
    
    # 获取文件信息
    files = []
    total_size_bytes = 0
    for filename in os.listdir(app.config['UPLOAD_FOLDER']):
        if os.path.isfile(os.path.join(app.config['UPLOAD_FOLDER'], filename)):
            file_info = get_file_info(filename)
            if file_info:
                files.append(file_info)
                # 获取文件实际大小（字节）
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                total_size_bytes += os.path.getsize(file_path)
    
    file_count = len(files)
    total_file_size = humanize.naturalsize(total_size_bytes)
    
    return render_template('admin.html', 
                           users=users, 
                           messages=messages, 
                           files=files, 
                           user_count=user_count, 
                           message_count=message_count, 
                           file_count=file_count, 
                           total_file_size=total_file_size)

# 删除用户路由
@app.route('/admin/delete_user', methods=['POST'])
@admin_required
def delete_user():
    username = request.form.get('username')
    
    # 获取用户数据
    users = get_safe_users()
    
    # 不允许删除管理员账户
    if username == 'admin':
        return redirect(url_for('admin_panel', error='不允许删除管理员账户'))
    
    if username in users:
        del users[username]
        save_users(users)
        return redirect(url_for('admin_panel', success=f'用户 {username} 已成功删除'))
    
    return redirect(url_for('admin_panel', error='用户不存在'))

# 删除留言路由
@app.route('/admin/delete_message', methods=['POST'])
@admin_required
def delete_message():
    try:
        message_index = int(request.form.get('message_index'))
        
        if 0 <= message_index < len(messages):
            deleted_message = messages.pop(message_index)
            save_messages()
            return redirect(url_for('admin_panel', success=f'留言已成功删除'))
        
        return redirect(url_for('admin_panel', error='留言索引无效'))
    except ValueError:
        return redirect(url_for('admin_panel', error='无效的留言索引'))

# 删除文件路由
@app.route('/admin/delete_file', methods=['POST'])
@admin_required
def delete_file():
    filename = request.form.get('filename')
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    if os.path.isfile(file_path):
        os.remove(file_path)
        
        # 同时从元数据中删除
        if filename in file_metadata:
            del file_metadata[filename]
            save_file_metadata()
        
        return redirect(url_for('admin_panel', success=f'文件 {filename} 已成功删除'))
    
    return redirect(url_for('admin_panel', error='文件不存在'))



if __name__ == '__main__':
    # 确保上传文件夹存在
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    app.run(debug=True, host='0.0.0.0', port=8000)

# 蜜罐路由 - 对用户不可见但对爬虫可见
@app.route('/admin/panel/')
@app.route('/wp-admin/')
@app.route('/phpmyadmin/')
@app.route('/login/admin/')
def honeypot():
    # 记录访问蜜罐的IP、User-Agent和时间
    client_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')
    access_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # 添加到蜜罐访问日志
    honeypot_access_log.append({
        'ip': client_ip,
        'user_agent': user_agent,
        'time': access_time
    })
    
    # 打印到控制台以便管理员查看
    print(f"蜜罐触发! IP: {client_ip}, User-Agent: {user_agent}, 时间: {access_time}")
    
    # 返回404错误，但不提供任何有用信息
    return "未找到页面", 404
