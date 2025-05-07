// 高级浏览器特征模拟脚本
// 这个脚本用于全面模拟Chrome浏览器的特征，以绕过网站的安全检测

(function() {
  // ==================== 基本属性模拟 ====================

  // 禁用webdriver标志
  Object.defineProperty(navigator, 'webdriver', {
    get: () => false
  });

  // 确保 languages 属性正确
  if (!navigator.languages || navigator.languages.length === 0) {
    Object.defineProperty(navigator, 'languages', {
      get: () => ['zh-CN', 'zh', 'en-US', 'en']
    });
  }

  // 设置标准的 productSub
  Object.defineProperty(navigator, 'productSub', {
    get: () => '20030107'
  });

  // 设置标准的 vendor
  Object.defineProperty(navigator, 'vendor', {
    get: () => 'Google Inc.'
  });

  // 设置标准的 maxTouchPoints
  Object.defineProperty(navigator, 'maxTouchPoints', {
    get: () => 0
  });

  // 设置标准的 hardwareConcurrency
  Object.defineProperty(navigator, 'hardwareConcurrency', {
    get: () => 8
  });

  // 设置标准的 deviceMemory
  if ('deviceMemory' in navigator) {
    Object.defineProperty(navigator, 'deviceMemory', {
      get: () => 8
    });
  }

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
      sendMessage: function() {},
      onConnect: {
        addListener: function() {},
        removeListener: function() {}
      },
      onMessage: {
        addListener: function() {},
        removeListener: function() {}
      },
      onInstalled: {
        addListener: function() {},
        removeListener: function() {}
      },
      getManifest: function() {
        return {
          version: '125.0.0.0'
        };
      }
    };
  }

  // 模拟 chrome.webstore
  if (!window.chrome.webstore) {
    window.chrome.webstore = {
      onInstallStageChanged: {
        addListener: function() {}
      },
      onDownloadProgress: {
        addListener: function() {}
      }
    };
  }

  // 模拟 chrome.app
  if (!window.chrome.app) {
    window.chrome.app = {
      isInstalled: false,
      getDetails: function() { return null; },
      getIsInstalled: function() { return false; },
      runningState: function() { return 'cannot_run'; }
    };
  }

  // 模拟 chrome.csi
  if (!window.chrome.csi) {
    window.chrome.csi = function() {
      return {
        startE: Date.now(),
        onloadT: Date.now(),
        pageT: Date.now(),
        tran: 15
      };
    };
  }

  // 模拟 chrome.loadTimes
  if (!window.chrome.loadTimes) {
    window.chrome.loadTimes = function() {
      return {
        commitLoadTime: Date.now() / 1000,
        connectionInfo: 'h2',
        finishDocumentLoadTime: Date.now() / 1000,
        finishLoadTime: Date.now() / 1000,
        firstPaintAfterLoadTime: 0,
        firstPaintTime: Date.now() / 1000,
        navigationType: 'Other',
        npnNegotiatedProtocol: 'h2',
        requestTime: Date.now() / 1000,
        startLoadTime: Date.now() / 1000,
        wasAlternateProtocolAvailable: false,
        wasFetchedViaSpdy: true,
        wasNpnNegotiated: true
      };
    };
  }

  // ==================== 浏览器插件模拟 ====================

  // 模拟 plugins 数组
  if (navigator.plugins.length === 0) {
    const pluginsData = [
      { name: 'Chrome PDF Plugin', description: 'Portable Document Format', filename: 'internal-pdf-viewer', length: 1 },
      { name: 'Chrome PDF Viewer', description: 'Portable Document Format', filename: 'internal-pdf-viewer', length: 1 },
      { name: 'Native Client', description: '', filename: 'internal-nacl-plugin', length: 1 },
      { name: 'Widevine Content Decryption Module', description: 'Enables Widevine licenses for playback of HTML audio/video content.', filename: 'widevinecdmadapter.dll', length: 1 }
    ];

    // 创建插件对象
    const plugins = {
      length: pluginsData.length,
      item: function(index) { return this[index] || null; },
      namedItem: function(name) {
        for (let i = 0; i < this.length; i++) {
          if (this[i].name === name) return this[i];
        }
        return null;
      },
      refresh: function() {}
    };

    // 添加插件
    pluginsData.forEach((plugin, index) => {
      plugins[index] = plugin;
    });

    // 替换 navigator.plugins
    Object.defineProperty(navigator, 'plugins', {
      get: () => plugins,
      enumerable: true,
      configurable: false
    });
  }

  // 模拟 mimeTypes
  if (navigator.mimeTypes.length === 0) {
    const mimeTypesData = [
      { type: 'application/pdf', suffixes: 'pdf', description: 'Portable Document Format' },
      { type: 'application/x-google-chrome-pdf', suffixes: 'pdf', description: 'Portable Document Format' },
      { type: 'application/x-nacl', suffixes: '', description: 'Native Client Executable' },
      { type: 'application/x-pnacl', suffixes: '', description: 'Portable Native Client Executable' },
      { type: 'application/x-widevine-cdm', suffixes: '', description: 'Widevine Content Decryption Module' }
    ];

    // 创建 mimeTypes 对象
    const mimeTypes = {
      length: mimeTypesData.length,
      item: function(index) { return this[index] || null; },
      namedItem: function(name) {
        for (let i = 0; i < this.length; i++) {
          if (this[i].type === name) return this[i];
        }
        return null;
      }
    };

    // 添加 mimeTypes
    mimeTypesData.forEach((mimeType, index) => {
      mimeTypes[index] = mimeType;
    });

    // 替换 navigator.mimeTypes
    Object.defineProperty(navigator, 'mimeTypes', {
      get: () => mimeTypes,
      enumerable: true,
      configurable: false
    });
  }

  // ==================== API 模拟 ====================

  // 修复 permissions API
  if ('permissions' in navigator) {
    const originalQuery = navigator.permissions.query;
    navigator.permissions.query = function(parameters) {
      if (parameters.name === 'notifications' ||
          parameters.name === 'clipboard-read' ||
          parameters.name === 'clipboard-write' ||
          parameters.name === 'geolocation' ||
          parameters.name === 'camera' ||
          parameters.name === 'microphone') {
        return Promise.resolve({ state: 'prompt', onchange: null });
      }
      return originalQuery.call(this, parameters);
    };
  }

  // 模拟 mediaDevices API
  if (!navigator.mediaDevices) {
    navigator.mediaDevices = {};
  }

  navigator.mediaDevices.enumerateDevices = navigator.mediaDevices.enumerateDevices || function() {
    return Promise.resolve([
      { deviceId: 'default', kind: 'audioinput', label: '', groupId: 'default' },
      { deviceId: 'default', kind: 'audiooutput', label: '', groupId: 'default' },
      { deviceId: 'default', kind: 'videoinput', label: '', groupId: 'default' }
    ]);
  };

  navigator.mediaDevices.getUserMedia = navigator.mediaDevices.getUserMedia || function() {
    return Promise.reject(new DOMException('Permission denied', 'NotAllowedError'));
  };

  // 模拟 Notification API
  if (!window.Notification) {
    window.Notification = {
      permission: 'default',
      requestPermission: function() {
        return Promise.resolve('default');
      }
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

  // 防止检测到 iframe 嵌套
  try {
    if (window.frameElement) {
      Object.defineProperty(window, 'frameElement', {
        get: () => null
      });
    }
  } catch (e) {}

  // 防止检测到 DevTools 协议
  if (window.devtoolsDetector) {
    delete window.devtoolsDetector;
  }

  // 模拟正常的屏幕和窗口尺寸
  if (window.outerWidth === 0 || window.outerHeight === 0) {
    Object.defineProperty(window, 'outerWidth', {
      get: () => window.innerWidth
    });
    Object.defineProperty(window, 'outerHeight', {
      get: () => window.innerHeight
    });
  }

  console.log('Advanced browser emulation script loaded successfully');
})();
