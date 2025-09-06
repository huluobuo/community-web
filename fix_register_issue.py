# 编程爱好者社区注册功能修复脚本
# 
# 根据调试分析，我们发现以下问题：
# 1. 服务器端的加密/解密密钥与前端不匹配（已修复）
# 2. 浏览器发送的注册请求返回了200状态码而非302重定向
# 3. 服务器日志显示内部测试请求正常重定向，但浏览器请求异常

# 修复方案包含两部分：
# 1. 修改前端register.html，确保表单正确提交
# 2. 在app.py中添加详细日志记录，便于进一步排查

import os
import shutil

# 创建备份
print("创建文件备份...")
if os.path.exists('templates/register.html'):
    shutil.copy2('templates/register.html', 'templates/register.html.bak')

if os.path.exists('app.py'):
    shutil.copy2('app.py', 'app.py.bak')

print("\n=== 修复方案说明 ===")
print("\n1. 前端修复：")
print("   - 简化register.html中的表单提交逻辑")
print("   - 移除可能导致问题的JavaScript代码")
print("   - 确保表单数据正确提交到服务器")

print("\n2. 后端修复：")
print("   - 已修复加密/解密密钥不匹配问题")
print("   - 添加详细的请求处理日志")
print("   - 增强错误处理和重定向逻辑")

print("\n=== 修复已完成 ===")
print("请查看以下修复后的文件内容，并将其应用到您的项目中。")
print("\n修复后的register.html内容：\n")

# 打印修复后的register.html内容
print('''
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>编程爱好者社区 - 注册</title>
    <link rel="stylesheet" href="/static/bootstrap/bootstrap.min.css">
    <link href="/static/css/custom.min.css" rel="stylesheet">
</head>
<body>
    <!-- 导航栏 -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container">
            <a class="navbar-brand" href="/">编程爱好者社区</a>
            <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ml-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="/login">登录</a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <!-- 主要内容 -->
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header text-center bg-primary text-white">
                        <h3>创建新账户</h3>
                    </div>
                    <div class="card-body">
                        <!-- 错误提示区域 -->
                        {% with messages = get_flashed_messages(with_categories=true) %}
                            {% if messages %}
                                {% for category, message in messages %}
                                    <div class="alert alert-{{ category }}" role="alert">
                                        {{ message }}
                                    </div>
                                {% endfor %}
                            {% endif %}
                        {% endwith %}

                        <!-- 注册表单 -->
                        <form method="POST" action="/register">
                            <div class="form-group">
                                <label for="username">用户名</label>
                                <input type="text" class="form-control" id="username" name="username" placeholder="请输入用户名" required>
                            </div>
                            <div class="form-group">
                                <label for="email">邮箱</label>
                                <input type="email" class="form-control" id="email" name="email" placeholder="请输入邮箱" required>
                            </div>
                            <div class="form-group">
                                <label for="password">密码</label>
                                <input type="password" class="form-control" id="password" name="password" placeholder="请输入密码" required>
                            </div>
                            <div class="form-group">
                                <label for="confirm_password">确认密码</label>
                                <input type="password" class="form-control" id="confirm_password" name="confirm_password" placeholder="请再次输入密码" required>
                            </div>
                            <button type="submit" class="btn btn-primary btn-block">注册</button>
                        </form>

                        <div class="text-center mt-3">
                            <p>已有账户？<a href="/login">立即登录</a></p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- 页脚 -->
    <footer class="footer mt-5 py-3 bg-light">
        <div class="container text-center">
            <span class="text-muted">© 2023 编程爱好者社区</span>
        </div>
    </footer>

    <!-- 脚本 -->
    <script src="/static/bootstrap/bootstrap.bundle.min.js"></script>
</body>
</html>
''')

print("\n修复后的app.py register_post函数内容：\n")

# 打印修复后的register_post函数内容
print('''
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
        'password': generate_password_hash(password, method='pbkdf2:sha256')
    }
    
    # 保存用户数据
    save_users(users)
    app.logger.info(f'注册成功: 用户 {username} 已创建')
    
    # 重定向到登录页面
    flash('注册成功！请登录', 'success')
    return redirect(url_for('login'))
''')

print("\n=== 应用修复步骤 ===")
print("1. 复制上面的register.html内容，替换您项目中的templates/register.html文件")
print("2. 复制上面的register_post函数内容，替换app.py中的对应函数")
print("3. 重启Flask服务器")
print("4. 清除浏览器缓存，然后尝试注册")

print("\n=== 修复说明 ===")
print("- 简化了前端表单，移除了可能导致问题的JavaScript代码")
print("- 使用标准的表单提交方式")
print("- 添加了详细的服务器日志，便于排查问题")
print("- 增强了错误处理逻辑")

print("\n如果修复后仍然有问题，请查看Flask服务器日志获取更多信息。")