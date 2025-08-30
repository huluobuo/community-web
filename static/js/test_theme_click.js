// 简单的主题切换测试脚本
document.addEventListener('DOMContentLoaded', function() {
    const themeToggle = document.getElementById('theme-toggle');
    console.log('测试脚本加载 - 主题切换按钮:', themeToggle);
    
    if (themeToggle) {
        console.log('测试脚本 - 添加点击事件监听器');
        themeToggle.addEventListener('click', function(e) {
            e.stopPropagation(); // 阻止事件冒泡
            console.log('测试脚本 - 按钮被点击!', e);
            alert('按钮被点击了! 测试成功!');
        });
    }
});