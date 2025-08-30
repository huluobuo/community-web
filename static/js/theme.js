// 简化版主题切换功能

// 读取cookie函数
function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
}

// 设置cookie函数
function setCookie(name, value, days = 30) {
    const date = new Date();
    date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
    const expires = `expires=${date.toUTCString()}`;
    document.cookie = `${name}=${value};${expires};path=/`;
}

// 初始化主题
document.addEventListener('DOMContentLoaded', function() {
    console.log('主题脚本加载完成');
    
    // 获取主题设置
    const cookieTheme = getCookie('theme');
    const savedTheme = localStorage.getItem('theme');
    const body = document.body;
    const themeToggle = document.getElementById('theme-toggle');
    
    console.log('主题切换按钮:', themeToggle);
    
    // 检查系统暗色模式偏好
    const prefersDarkMode = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    
    // 设置初始主题
    if (cookieTheme === 'dark' || (cookieTheme === undefined && savedTheme === 'dark') || (!cookieTheme && !savedTheme && prefersDarkMode)) {
        enableDarkMode();
    } else {
        enableLightMode();
    }
    
    // 添加主题切换事件监听
    if (themeToggle) {
        console.log('添加主题切换事件监听');
        themeToggle.addEventListener('click', function(e) {
            e.preventDefault();
            e.stopPropagation();
            console.log('主题切换按钮被点击!');
            if (body.classList.contains('dark-mode')) {
                enableLightMode();
            } else {
                enableDarkMode();
            }
        });
    } else {
        console.log('未找到主题切换按钮');
    }
    
    // 启用暗色模式
    function enableDarkMode() {
        console.log('启用暗色模式');
        body.classList.add('dark-mode');
        body.classList.remove('bg-light');
        
        // 更新导航栏样式
        const navbar = document.querySelector('.navbar');
        if (navbar) {
            navbar.classList.remove('bg-primary');
            navbar.classList.add('bg-dark');
        }
        
        // 更新卡片样式
        const cards = document.querySelectorAll('.card, .message, .jumbotron');
        cards.forEach(el => {
            if (el.classList.contains('bg-white')) {
                el.classList.remove('bg-white');
                el.classList.add('bg-dark', 'text-white', 'border', 'border-gray-700');
            }
        });
        
        // 更新页脚样式
        const footer = document.querySelector('footer');
        if (footer) {
            footer.classList.add('bg-dark');
            footer.classList.remove('bg-gray-800');
        }
        
        // 更新主题切换按钮图标
        if (themeToggle) {
            const icon = themeToggle.querySelector('i');
            if (icon) {
                icon.classList.remove('fa-moon');
                icon.classList.add('fa-sun');
            }
        }
        
        // 保存主题设置
        localStorage.setItem('theme', 'dark');
        setCookie('theme', 'dark');
        document.documentElement.setAttribute('data-theme', 'dark');
    }
    
    // 启用亮色模式
    function enableLightMode() {
        console.log('启用亮色模式');
        body.classList.remove('dark-mode');
        body.classList.add('bg-light');
        
        // 更新导航栏样式
        const navbar = document.querySelector('.navbar');
        if (navbar) {
            navbar.classList.add('bg-primary');
            navbar.classList.remove('bg-dark');
        }
        
        // 更新卡片样式
        const cards = document.querySelectorAll('.card, .message, .jumbotron');
        cards.forEach(el => {
            if (el.classList.contains('bg-dark')) {
                el.classList.add('bg-white');
                el.classList.remove('bg-dark', 'text-white', 'border', 'border-gray-700');
            }
        });
        
        // 更新页脚样式
        const footer = document.querySelector('footer');
        if (footer) {
            footer.classList.remove('bg-dark');
            footer.classList.add('bg-gray-800');
        }
        
        // 更新主题切换按钮图标
        if (themeToggle) {
            const icon = themeToggle.querySelector('i');
            if (icon) {
                icon.classList.add('fa-moon');
                icon.classList.remove('fa-sun');
            }
        }
        
        // 保存主题设置
        localStorage.setItem('theme', 'light');
        setCookie('theme', 'light');
        document.documentElement.setAttribute('data-theme', 'light');
    }
});