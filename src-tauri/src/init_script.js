// 高级浏览器特征模拟脚本 - 初始化版本
// 这个脚本在WebView初始化时运行，提供基本的浏览器模拟

// ==================== 基本属性模拟 ====================

// 禁用webdriver标志
Object.defineProperty(navigator, 'webdriver', {
    get: () => false
});

// 设置标准的 vendor
Object.defineProperty(navigator, 'vendor', {
    get: () => 'Google Inc.'
});

// 设置标准的 productSub
Object.defineProperty(navigator, 'productSub', {
    get: () => '20030107'
});

// ==================== Chrome 对象模拟 ====================

// 创建完整的 chrome 对象
if (!window.chrome) {
    window.chrome = {};
}

// 模拟 chrome.runtime
if (!window.chrome.runtime) {
    window.chrome.runtime = {
        id: '',
        connect: function() {
            return {
                onDisconnect: {
                    addListener: function() {}
                },
                onMessage: {
                    addListener: function() {}
                },
                postMessage: function() {}
            };
        },
        sendMessage: function() {}
    };
}

// 模拟 chrome.webstore
if (!window.chrome.webstore) {
    window.chrome.webstore = {
        onInstallStageChanged: {},
        onDownloadProgress: {}
    };
}

// 模拟 chrome.app
if (!window.chrome.app) {
    window.chrome.app = {
        isInstalled: false
    };
}

// ==================== 防检测技术 ====================

// 防止检测到 WebDriver
const originalHasOwnProperty = Object.prototype.hasOwnProperty;
Object.prototype.hasOwnProperty = function(property) {
    if (property === 'webdriver') {
        return false;
    }
    return originalHasOwnProperty.call(this, property);
};

// 防止检测到自动化
delete window.cdc_adoQpoasnfa76pfcZLmcfl_Array;
delete window.cdc_adoQpoasnfa76pfcZLmcfl_Promise;
delete window.cdc_adoQpoasnfa76pfcZLmcfl_Symbol;

console.log('Advanced browser initialization script loaded');
