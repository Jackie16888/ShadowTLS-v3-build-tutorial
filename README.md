# **说明**
脚本采用官方配置，只是把搭建步骤自动化，无安全隐患，放心使用。
- **一键安装**
```
apt install -y curl
```
```
bash <(curl -L https://raw.githubusercontent.com/TinrLin/ShadowTLS-v3-build-tutorial/main/Install.sh)
```
- **卸载步骤**

1.停止sing-box服务：
```
systemctl stop sing-box
```
2.禁用sing-box服务的开机自启服务：
```
systemctl disable sing-box
```
3.删除sing-box的配置文件和开机自启服务文件：
```
rm /etc/systemd/system/sing-box.service
```
```
rm -rf /usr/local/etc/sing-box
```
4.删除sing-box程序文件：
```
rm /usr/local/bin/sing-box
```
