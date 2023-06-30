#!/bin/bash

# 更新软件源及安装组件
echo "更新软件源..."
apt update && apt -y install wget

# 开启 BBR
echo "开启 BBR..."
echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
sysctl -p

echo "BBR 已开启"

# 选择 sing-box 安装方式
sing_box_install_option=""

while [[ $sing_box_install_option != "1" && $sing_box_install_option != "2" ]]; do
    read -p $'\e[36m请选择 sing-box 的安装方式 
1.自行编译
2.下载已编译的sing-box
请选择 [1/2]: \e[0m' sing_box_install_option

    if [[ $sing_box_install_option != "1" && $sing_box_install_option != "2" ]]; then
        echo -e "\e[31m无效的选择，请重新输入。\e[0m"
    fi
done

if [[ $sing_box_install_option == "1" ]]; then
    # 自行编译 sing-box
    echo "下载并安装 Go..."
    if [[ $(arch) == "x86_64" ]]; then
        wget -c https://go.dev/dl/go1.20.5.linux-amd64.tar.gz -O - | tar -xz -C /usr/local 
    elif [[ $(arch) == "aarch64" ]]; then
        wget -c https://go.dev/dl/go1.20.5.linux-arm64.tar.gz -O - | tar -xz -C /usr/local 
    else
        echo "不支持的架构: $(arch)"
        exit 1
    fi

    echo 'export PATH=$PATH:/usr/local/go/bin' > /etc/profile
    source /etc/profile

    echo "编译安装 sing-box..."
    go install -v -tags \
    with_dhcp,\
    with_wireguard,\
    with_ech,\
    with_utls,\
    with_clash_api,\
    with_v2ray_api,\
    with_gvisor,\
    with_lwip \
    github.com/sagernet/sing-box/cmd/sing-box@latest
    cp ~/go/bin/sing-box /usr/local/bin/
    chmod +x /usr/local/bin/sing-box

elif [[ $sing_box_install_option == "2" ]]; then
    # 下载已编译的 sing-box
    if [[ $(arch) == "x86_64" ]]; then
        echo "下载并安装预编译的 sing-box (AMD 内核)..."
        wget -c https://github.com/SagerNet/sing-box/releases/download/v1.3.0/sing-box-1.3.0-linux-amd64.tar.gz -O - | tar -xz -C /usr/local/bin --strip-components=1
    elif [[ $(arch) == "aarch64" ]]; then
        echo "下载并安装预编译的 sing-box (ARM 内核)..."
        wget -c https://github.com/SagerNet/sing-box/releases/download/v1.3.0/sing-box-1.3.0-linux-arm64.tar.gz -O - | tar -xz -C /usr/local/bin --strip-components=1
    else
        echo "不支持的架构: $(arch)"
        exit 1
    fi
    
    chmod +x /usr/local/bin/sing-box
    
fi
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
read -p $'\e[36m请输入监听端口 (默认443): \e[0m' listen_port

while true; do
    if [[ $listen_port =~ ^[1-9][0-9]{0,4}$ && $listen_port -le 65535 ]]; then
        echo -e "\e[32m监听端口设置成功：$listen_port\e[0m"
        break
    elif [[ -z $listen_port ]]; then
        listen_port=443
        echo -e "\e[32m监听端口设置成功：$listen_port\e[0m"
        break
    else
        echo -e "\e[31m错误：监听端口范围必须在1-65535之间，请重新输入。\e[0m"
        read -p $'\e[36m请输入监听端口 (默认443): \e[0m' listen_port
    fi
done

read -p $'\e[36m请输入用户名 (默认随机生成): \e[0m' new_username
username=${new_username:-$username}

echo -e "\e[32m用户名: $username\e[0m"

# 生成ShadowTLS密码
read -p $'\e[36m请选择Shadowsocks加密方式：
1. 2022-blake3-chacha20-poly1305
2. 2022-blake3-aes-256-gcm
3. 2022-blake3-aes-128-gcm
请输入对应的数字 (默认1): \e[0m' encryption_choice
encryption_choice=${encryption_choice:-1}

case $encryption_choice in
    1)
        ss_method="2022-blake3-chacha20-poly1305"
        shadowtls_password=$(openssl rand -base64 32)
        ss_password=$(openssl rand -base64 32)
        ;;
    2)
        ss_method="2022-blake3-aes-256-gcm"
        shadowtls_password=$(openssl rand -base64 32)
        ss_password=$(openssl rand -base64 32)
        ;;
    3)
        ss_method="2022-blake3-aes-128-gcm"
        shadowtls_password=$(openssl rand -base64 16)
        ss_password=$(openssl rand -base64 16)
        ;;
    *)
        echo -e "\e[31m无效的选择，默认使用2022-blake3-chacha20-poly1305加密方式。\e[0m"
        ss_method="2022-blake3-chacha20-poly1305"
        shadowtls_password=$(openssl rand -base64 32)
        ss_password=$(openssl rand -base64 32)
        ;;
esac

read -p $'\e[36m请输入握手服务器地址 (默认www.apple.com): \e[0m' handshake_server
handshake_server=${handshake_server:-www.apple.com}

# 验证握手服务器是否支持TLS 1.3
echo -e "\e[36m正在验证握手服务器支持的TLS版本...\e[0m"

while true; do
    openssl_output=$(openssl s_client -connect "$handshake_server:443" -tls1_3 2>&1)

    if [[ $openssl_output == *"Protocol  : TLSv1.3"* ]]; then
        echo -e "\e[36m握手服务器支持TLS 1.3。\e[0m"
        break
    else
        echo -e "\e[31m错误：握手服务器不支持TLS 1.3，请重新输入握手服务器地址。\e[0m"
        read -p $'\e[36m请输入握手服务器地址 (默认www.apple.com): \e[0m' handshake_server
        handshake_server=${handshake_server:-www.apple.com}
        echo -e "\e[36m正在验证握手服务器支持的TLS版本...\e[0m"
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

# 显示配置信息
echo -e "\e[32m---------------------\e[0m"
echo -e "\e[32msing-box已成功安装和配置。\e[0m"
echo -e "\e[32m配置信息如下：\e[0m"
echo -e "\e[32m用户名: $username\e[0m"
echo -e "\e[32m监听端口: $listen_port\e[0m"
echo -e "\e[32mShadowsocks加密方式: $ss_method\e[0m"
echo -e "\e[32mShadowTLS密码: $shadowtls_password\e[0m"
echo -e "\e[32mShadowsocks密码: $ss_password\e[0m"
echo -e "\e[32m握手服务器地址: $handshake_server\e[0m"
echo -e "\e[32m---------------------\e[0m"
