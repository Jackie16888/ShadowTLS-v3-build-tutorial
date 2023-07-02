# **说明**
该脚本有自行编译和下载预编译版的sing-box两种选择，所有代码均来自官方文档;该脚本完全开源，您可以放心使用！

sing-box可执行文件目录：/usr/local/bin/sing-box

sing-box的systemd服务目录：/etc/systemd/system/sing-box.service

sing-box配置文件目录：/usr/local/etc/sing-box/config.json

# **一键安装**
```
apt update && apt-get -y install wget jq tar git libc6-dev build-essential zlib1g-dev libssl-dev libevent-dev mingw-w64
```
```
bash <(curl -L https://raw.githubusercontent.com/TinrLin/ShadowTLS-v3-build-tutorial/main/Install.sh)
```
# **手动安装**

- **下载预编译版sing-box**
- AMD 内核
```
wget -c "https://github.com/SagerNet/sing-box/releases/download/v1.3.0/sing-box-1.3.0-linux-amd64.tar.gz" -O - | tar -xz -C /usr/local/bin --strip-components=1 && chmod +x /usr/local/bin/sing-box
```
- AMD 内核
```
wget -c "https://github.com/SagerNet/sing-box/releases/download/v1.3.0/sing-box-1.3.0-linux-arm64.tar.gz" -O - | tar -xz -C /usr/local/bin --strip-components=1 && chmod +x /usr/local/bin/sing-box
```
- **Disable the boot self-starting service of the sing-box service**
```
systemctl disable sing-box
```
- **Delete the configuration file and self-start service file of sing-box**
```
rm /etc/systemd/system/sing-box.service
```
```
rm -rf /usr/local/etc/sing-box
```
- **Delete the sing-box program file**
```
rm /usr/local/bin/sing-box
```
