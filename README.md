# **说明**
该脚本有自行编译和下载预编译版的sing-box两种选择，所有代码均来自官方文档;该脚本完全开源，您可以放心使用！
sing-box可执行文件目录：/usr/local/bin/sing-box
sing-box的systemd服务目录：/etc/systemd/system/sing-box.service
sing-box配置文件目录：/usr/local/etc/sing-box/config.json

# **一键安装**
```
apt update && apt-get -y install wget jq tar
```
```
bash <(curl -L https://raw.githubusercontent.com/TinrLin/ShadowTLS-v3-build-tutorial/main/Install.sh)
```
# **手动安装**

- **stop sing-box service**
```
systemctl stop sing-box
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
