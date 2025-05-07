#!/bin/bash

# 创建图标目录
mkdir -p src-tauri/icons

# 下载 Gemini 图标
echo "下载 Gemini 图标..."
curl -o src-tauri/icons/gemini.png "https://upload.wikimedia.org/wikipedia/commons/f/f0/Google_Gemini_icon.svg" 

# 下载 Poe 图标
echo "下载 Poe 图标..."
curl -o src-tauri/icons/poe.png "https://poe.com/favicon.ico"

# 下载应用程序图标
echo "下载应用程序图标..."
curl -o src-tauri/icons/app.png "https://cdn-icons-png.flaticon.com/512/2175/2175377.png"

# 创建不同尺寸的图标
echo "创建不同尺寸的图标..."
convert src-tauri/icons/app.png -resize 32x32 src-tauri/icons/32x32.png
convert src-tauri/icons/app.png -resize 128x128 src-tauri/icons/128x128.png
convert src-tauri/icons/app.png -resize 256x256 src-tauri/icons/128x128@2x.png

# 创建 .ico 文件 (Windows)
echo "创建 .ico 文件..."
convert src-tauri/icons/app.png -define icon:auto-resize=16,32,48,64,128,256 src-tauri/icons/icon.ico

# 创建 .icns 文件 (macOS)
echo "创建 .icns 文件..."
mkdir -p src-tauri/icons/iconset
convert src-tauri/icons/app.png -resize 16x16 src-tauri/icons/iconset/icon_16x16.png
convert src-tauri/icons/app.png -resize 32x32 src-tauri/icons/iconset/icon_16x16@2x.png
convert src-tauri/icons/app.png -resize 32x32 src-tauri/icons/iconset/icon_32x32.png
convert src-tauri/icons/app.png -resize 64x64 src-tauri/icons/iconset/icon_32x32@2x.png
convert src-tauri/icons/app.png -resize 128x128 src-tauri/icons/iconset/icon_128x128.png
convert src-tauri/icons/app.png -resize 256x256 src-tauri/icons/iconset/icon_128x128@2x.png
convert src-tauri/icons/app.png -resize 256x256 src-tauri/icons/iconset/icon_256x256.png
convert src-tauri/icons/app.png -resize 512x512 src-tauri/icons/iconset/icon_256x256@2x.png
convert src-tauri/icons/app.png -resize 512x512 src-tauri/icons/iconset/icon_512x512.png
convert src-tauri/icons/app.png -resize 1024x1024 src-tauri/icons/iconset/icon_512x512@2x.png
iconutil -c icns -o src-tauri/icons/icon.icns src-tauri/icons/iconset
rm -rf src-tauri/icons/iconset

echo "图标下载和转换完成！"
