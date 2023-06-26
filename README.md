# **Illustrate**
脚本采用官方配置，只是把搭建步骤自动化，无安全隐患，放心使用。
- **Installation**
```
apt install -y curl
```
```
bash <(curl -L https://raw.githubusercontent.com/TinrLin/ShadowTLS-v3-build-tutorial/main/Install.sh)
```
- **Uninstall**

1.stop sing-box service：
```
systemctl stop sing-box
```
2.Disable the boot self-starting service of the sing-box service：
```
systemctl disable sing-box
```
3.Delete the configuration file and self-start service file of sing-box：
```
rm /etc/systemd/system/sing-box.service
```
```
rm -rf /usr/local/etc/sing-box
```
4.Delete the sing-box program file：
```
rm /usr/local/bin/sing-box
```
