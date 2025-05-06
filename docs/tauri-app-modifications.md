# Tauri 应用修改文档

## 项目概述

本项目是使用 Tauri 框架创建的桌面应用，目的是将网站包装成桌面应用程序，提供更好的用户体验。应用最初配置为打开 Poe.com，后来修改为打开 Google Gemini。

## 主要修改内容

### 1. 配置文件更新 (tauri.conf.json)

#### 原因
Tauri 2.0 版本对配置文件格式进行了重大更改，需要更新配置文件以符合新的格式要求。

#### 修改内容
- 添加了 `$schema` 字段，指向 Tauri 2.0 的配置模式
- 将 `devPath` 和 `distDir` 更改为 `devUrl` 和 `frontendDist`
- 将嵌套的配置结构调整为符合 Tauri 2.0 的格式
- 更新了 `productName` 和窗口标题
- 更新了目标 URL 从 Poe.com 到 Gemini

### 2. 添加 Capabilities 文件

#### 原因
Tauri 2.0 引入了一个新的权限系统，称为 Capabilities。这是一种更安全的方式来声明应用需要的权限，遵循最小权限原则。每个 capability 文件定义了应用可以访问的资源和执行的操作。

#### 修改内容

##### default.json
```json
{
  "identifier": "default",
  "description": "Default capabilities",
  "permissions": [
    "core:default",
    "core:window:default",
    "core:webview:default"
  ]
}
```

这个文件定义了应用的基本权限，包括：
- `core:default`: 基本的核心功能权限
- `core:window:default`: 窗口操作的权限（如创建、调整大小等）
- `core:webview:default`: WebView 操作的权限（如加载 URL、执行脚本等）

##### gemini.json (原 poe.json)
```json
{
  "identifier": "gemini",
  "description": "Google Gemini capabilities",
  "permissions": [
    {
      "identifier": "http:default",
      "allow": [
        {
          "url": "https://*.google.com"
        },
        {
          "url": "https://gemini.google.com"
        }
      ]
    }
  ]
}
```

这个文件定义了应用可以访问的网络资源：
- `http:default`: 允许应用发起 HTTP 请求
- `allow` 数组指定了允许访问的 URL 模式，这里允许访问 Google Gemini 相关的域名

### 3. 更新 Cargo.toml

#### 原因
需要更新 Rust 依赖以支持 Tauri 2.0 版本，并添加 HTTP 插件以支持网络请求。

#### 修改内容
- 将 `tauri` 和 `tauri-build` 依赖版本更新到 2.0.0
- 添加 `tauri-plugin-http` 依赖
- 更新 `custom-protocol` 特性为 `protocol-asset`

### 4. 更新 main.rs

#### 原因
需要初始化 HTTP 插件以支持网络请求，并适应 Tauri 2.0 的 API 变化。

#### 修改内容
- 添加 `tauri_plugin_http::init()` 插件初始化
- 简化了 `setup` 函数

### 5. 内容安全策略 (CSP) 更新

#### 原因
为了允许应用安全地加载 Google Gemini 网站的资源，需要配置适当的内容安全策略。

#### 修改内容
更新了 CSP 以允许从 Google Gemini 域名加载资源：
```
"csp": "default-src 'self' https://gemini.google.com https://*.google.com; style-src 'self' 'unsafe-inline' https://gemini.google.com https://*.google.com; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://gemini.google.com https://*.google.com; img-src 'self' data: https: http:; connect-src 'self' https: wss:;"
```

## 技术细节

### Capabilities 系统解释

Tauri 2.0 引入的 Capabilities 系统是一种声明式权限模型，它允许开发者明确指定应用需要的权限，并且可以在运行时由用户授予或拒绝。这种方法提高了应用的安全性，因为：

1. **最小权限原则**：应用只获得它明确需要的权限，而不是所有可能的权限
2. **透明性**：用户可以清楚地看到应用请求的权限
3. **细粒度控制**：权限可以非常具体，例如只允许访问特定的 URL

每个 capability 文件包含以下关键部分：

- `identifier`：唯一标识符，用于引用这个 capability
- `description`：描述这个 capability 的用途
- `permissions`：具体的权限列表，可以是简单的字符串或包含更多配置的对象

### 为什么需要 HTTP 插件

在 Tauri 2.0 中，核心功能被拆分成多个插件，以减小应用的大小并提高安全性。HTTP 功能现在是一个单独的插件，需要明确添加和初始化才能使用。这样，如果应用不需要网络功能，就不会包含相关代码，从而减小应用体积并提高安全性。

## 构建和运行

要构建和运行这个应用，请使用以下命令：

```bash
# 开发模式运行
cargo tauri dev

# 构建发布版本
cargo tauri build
```

## 未来改进方向

1. 添加自定义图标，使应用看起来更专业
2. 添加系统托盘图标，允许应用最小化到系统托盘
3. 添加快捷键支持，如刷新页面或切换全屏模式
4. 实现自动登录或其他便捷功能
5. 添加离线支持或缓存功能
