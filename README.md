
# **installation**

- ## **Download the precompiled version of sing-box**
- AMD core
```
wget -c "https://github.com/SagerNet/sing-box/releases/download/v1.3.0/sing-box-1.3.0-linux-amd64.tar.gz" -O - | tar -xz -C /usr/local/bin --strip-components=1 && chmod +x /usr/local/bin/sing-box
```
- ARM core
```
wget -c "https://github.com/SagerNet/sing-box/releases/download/v1.3.0/sing-box-1.3.0-linux-arm64.tar.gz" -O - | tar -xz -C /usr/local/bin --strip-components=1 && chmod +x /usr/local/bin/sing-box
```
- ## **Configure the systemd service of sing-box**
```
wget -P /etc/systemd/system https://raw.githubusercontent.com/TinrLin/ShadowTLS-v3-build-tutorial/main/sing-box.service
```
- ## **Download and modify the sing-box configuration file**
```
mkdir /usr/local/etc/sing-box && wget -P /usr/local/etc/sing-box https://raw.githubusercontent.com/TinrLin/ShadowTLS-v3-build-tutorial/main/config.json
```
- ## **Start and run sing-box**
```
systemctl daemon-reload && systemctl enable --now sing-box && systemctl status sing-box
```
