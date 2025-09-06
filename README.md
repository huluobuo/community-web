# 社区网站项目

这是一个使用Flask框架开发的社区网站，提供用户认证、消息交流、文件共享等功能。

最近更新：修复了登录功能的重定向问题，为下载功能添加了登录限制，增强了用户体验和安全性。

## 项目特点

- 用户注册、登录和管理功能，包含登录验证失败的重定向优化
- 消息板系统，支持用户间交流
- 文件上传和下载功能，下载功能增加登录限制
- 深色/浅色主题切换
- 响应式设计，支持多种设备

## 目录结构

```
├── .env                # 环境变量配置文件
├── .gitignore          # Git忽略文件
├── README.md           # 项目说明文档
├── app.py              # Flask应用主文件
├── convert_favicon.py  # 图标转换工具
├── file_metadata.json  # 文件元数据
├── files/              # 上传文件存储目录
├── messages.json       # 消息板数据
├── requirements.txt    # 项目依赖
├── static/             # 静态资源文件
│   ├── css/            # 样式文件
│   ├── fonts/          # 字体文件
│   ├── html/           # HTML页面文件
│   ├── img/            # 图片资源
│   └── js/             # JavaScript脚本
├── tests/              # 测试文件目录
└── users.json          # 用户数据
```

## 安装指南

### 前提条件

- Python 3.7+
- pip包管理器

### 安装步骤

1. 克隆项目仓库
2. 安装依赖：

   ```bash
   pip install -r requirements.txt
   ```
3. 创建 `.env`文件并配置环境变量（如需要）
4. 运行应用：

   ```bash
   python app.py
   ```
5. 打开浏览器访问 `http://localhost:8000`

   > 注：管理员账号是 ：`admin`，默认密码是：`admin123`
   >
   > ---
   >
   > 密码可以 `.env`文件里更改
   >

## 功能说明

### 用户系统

- 注册新用户
- 用户登录和注销
- 用户信息管理

### 消息板

- 发布新消息
- 查看所有消息
- 消息按时间排序

### 文件共享

- 上传文件（需要登录）
- 查看文件列表
- 下载文件（需要登录，增强安全性）

### 主题切换

- 支持深色模式和浅色模式
- 自动记忆用户偏好设置

## 技术栈

- 后端：Python Flask
- 前端：HTML, CSS, JavaScript
- 数据存储：JSON文件
- 样式：Bootstrap

## 开发说明

### 添加新页面

1. 在 `static/html/`目录下创建新的HTML文件
2. 确保在页面中正确引入CSS和JavaScript文件
3. 在 `app.py`中添加对应的路由

### 修改主题

- 修改 `static/css/custom.css`文件自定义样式
- 修改 `static/js/theme.js`文件调整主题切换逻辑

## 许可证

本项目使用 MIT 许可证

Copyright (c) 2025 huluobuo

[MIT许可证全文](https://opensource.org/licenses/MIT)

## 贡献

欢迎提交Issue和Pull Request来改进这个项目！
