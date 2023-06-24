# [ShadowTLS v3](https://github.com/ihciah/shadow-tls/tree/master)
- **Install dependencies**
```
apt update && apt -y install wget
```
- **Install sing-box**
```
wget -c https://github.com/SagerNet/sing-box/releases/download/v1.3-rc2/sing-box-1.3-rc2-linux-amd64.tar.gz -O - | tar -xz -C /usr/local/bin --strip-components=1 && chmod +x /usr/local/bin/sing-box
```
- **Download sing-box.service and config.json**
```
wget -P /etc/systemd/system https://raw.githubusercontent.com/TinrLin/ShadowTLS-v3-build-tutorial/main/sing-box.service && mkdir /usr/local/etc/sing-box && wget -P /usr/local/etc/sing-box https://raw.githubusercontent.com/TinrLin/ShadowTLS-v3-build-tutorial/main/config.json
```
- **Test if it works**
```
/usr/local/bin/sing-box run -c /usr/local/etc/sing-box/config.json
```
- **Check the current status**
```
systemctl daemon-reload && systemctl enable --now sing-box && systemctl status sing-box
