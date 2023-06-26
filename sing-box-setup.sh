#!/bin/bash

# 更新软件源
echo "更新软件源..."
apt update

# 安装 wget
echo "安装 wget..."
apt install -y wget

# 检查 wget 是否安装成功
if ! command -v wget &>/dev/null; then
    echo "安装 wget 失败。请检查软件源配置后重试。"
    exit 1
fi

echo "wget 安装完成。"

# 开启BBR加速
echo "开启BBR加速..."
echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
sysctl -p

# 下载并安装 sing-box 程序
if [[ $(arch) == "x86_64" ]]; then
    wget -c https://github.com/SagerNet/sing-box/releases/download/v1.3-rc2/sing-box-1.3-rc2-linux-amd64.tar.gz -O - | tar -xz -C /usr/local/bin --strip-components=1
elif [[ $(arch) == "aarch64" ]]; then
    wget -c https://github.com/SagerNet/sing-box/releases/download/v1.3-rc2/sing-box-1.3-rc2-linux-arm64.tar.gz -O - | tar -xz -C /usr/local/bin --strip-components=1
else
    echo "Unsupported architecture: $(arch)"
    exit 1
fi

# 赋予 sing-box 可执行权限
chmod +x /usr/local/bin/sing-box

echo "sing-box 安装完成。"

# 配置开机自启服务
echo "配置sing-box开机自启服务..."
echo "[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
ExecStart=/usr/local/bin/sing-box run -c /usr/local/etc/sing-box/config.json
Restart=on-failure
RestartSec=1800s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target" | tee /etc/systemd/system/sing-box.service

# 创建sing-box配置文件
echo "创建sing-box配置文件..."
mkdir -p /usr/local/etc/sing-box
config_file="/usr/local/etc/sing-box/config.json"

# 生成随机用户名
username=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 8 | head -n 1)
read -p "请输入监听端口 (默认443): " listen_port

while true; do
    if [[ $listen_port =~ ^[1-9][0-9]{0,4}$ && $listen_port -le 65535 ]]; then
        break
    elif [[ -z $listen_port ]]; then
        listen_port=443
        break
    else
        echo "错误：监听端口范围必须在1-65535之间，请重新输入。"
        read -p "请输入监听端口 (默认443): " listen_port
    fi
done

read -p "请输入用户名 (默认随机生成): " new_username
username=${new_username:-$username}

# 生成ShadowTLS密码
read -p "请选择Shadowsocks加密方式：
1. 2022-blake3-aes-128-gcm
2. 2022-blake3-aes-256-gcm
3. 2022-blake3-chacha20-poly1305
请输入对应的数字 (默认1): " encryption_choice
encryption_choice=${encryption_choice:-1}

case $encryption_choice in
    1)
        ss_method="2022-blake3-aes-128-gcm"
        shadowtls_password=$(openssl rand -base64 16)
        ss_password=$shadowtls_password
        ;;
    2)
        ss_method="2022-blake3-aes-256-gcm"
        shadowtls_password=$(openssl rand -base64 32)
        ss_password=$shadowtls_password
        ;;
    3)
        ss_method="2022-blake3-chacha20-poly1305"
        shadowtls_password=$(openssl rand -base64 32)
        ss_password=$shadowtls_password
        ;;
    *)
        echo "无效的选择，默认使用2022-blake3-aes-128-gcm加密方式。"
        ss_method="2022-blake3-aes-128-gcm"
        shadowtls_password=$(openssl rand -base64 16)
        ss_password=$shadowtls_password
        ;;
esac

read -p "请输入握手服务器地址 (默认www.apple.com): " handshake_server
handshake_server=${handshake_server:-www.apple.com}

# 验证握手服务器是否支持TLS 1.3
echo "正在验证握手服务器支持的TLS版本..."

while true; do
    openssl_output=$(openssl s_client -connect "$handshake_server:443" -tls1_3 2>&1)

    if [[ $openssl_output == *"Protocol  : TLSv1.3"* ]]; then
        echo "握手服务器支持TLS 1.3。"
        break
    else
        echo "错误：握手服务器不支持TLS 1.3，请重新输入握手服务器地址。"
        read -p "请输入握手服务器地址 (默认www.apple.com): " handshake_server
        handshake_server=${handshake_server:-www.apple.com}
        echo "正在验证握手服务器支持的TLS版本..."
    fi
done


# 写入配置文件
echo "{
  \"inbounds\": [
    {
      \"type\": \"shadowtls\",
      \"tag\": \"st-in\",
      \"listen\": \"::\",
      \"listen_port\": $listen_port,
      \"version\": 3,
      \"users\": [
        {
          \"name\": \"$username\",
          \"password\": \"$shadowtls_password\"
        }
      ],
      \"handshake\": {
        \"server\": \"$handshake_server\",
        \"server_port\": 443
      },
      \"strict_mode\": true,
      \"detour\": \"ss-in\"
    },
    {
      \"type\": \"shadowsocks\",
      \"tag\": \"ss-in\",
      \"listen\": \"127.0.0.1\",
      \"network\": \"tcp\",
      \"method\": \"$ss_method\",
      \"password\": \"$ss_password\"
    }
  ],
  \"outbounds\": [
    {
      \"type\": \"direct\",
      \"tag\": \"direct\"
    },
    {
      \"type\": \"block\",
      \"tag\": \"block\"
    }
  ]
}" > "$config_file"

echo "配置文件已生成。"

# 检查 UFW 是否已启用
ufw_status=$(ufw status 2>/dev/null | grep "Status: active")

if [[ -n $ufw_status ]]; then
    # 检查监听端口是否已放行
    ufw_rule=$(ufw status numbered | grep " $listen_port ")
    
    if [[ -z $ufw_rule ]]; then
        # 放行监听端口
        ufw allow "$listen_port"
        echo "已放行监听端口 $listen_port。"
    else
        echo "监听端口 $listen_port 已放行。"
    fi
else
    echo "UFW 防火墙未启用或未检测到 UFW。不需要设置监听端口的放行规则。"
fi

# 启动 sing-box 服务
echo "启动 sing-box 服务..."
systemctl daemon-reload
systemctl enable sing-box
systemctl start sing-box

# 检查 sing-box 的启动状态
echo "检查 sing-box 的启动状态..."
systemctl status sing-box

# 显示配置信息
echo "---------------------"
echo "sing-box已成功安装和配置。"
echo "配置信息如下："
echo "用户名: $username"
echo "监听端口: $listen_port"
echo "Shadowsocks加密方式: $ss_method"
echo "ShadowTLS密码: $shadowtls_password"
echo "握手服务器地址: $handshake_server"
echo "---------------------"
