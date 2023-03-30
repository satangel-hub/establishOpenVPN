# establishOpenVPN
Method of building VPN using openvpn
概念
OpenVPN 是一个开源的应用程序，它允许您通过公共互联网创建一个安全的专用网络。OpenVPN 实现一个虚拟专用网（VPN）来创建一个安全连接。OpenVPN 使用 OpenSSL 库提供加密，它提供了几种身份验证机制，如基于证书的、预共享密钥和用户名/密码身份验证，这里记录下基于证书的方式。

前提
搭建和使用 OpenVPN 认证服务有一个前提，就是要确保服务器 Server 和 客户端 Client 的时间要正确，不然会导致后续证书验证不通过，无法建立连接。

CentOS7 永久修改系统时间
操作步骤如下： - 查看当前系统时间 date - 修改当前系统时间 date -s "2020-07-02 23:49:30" - 查看硬件时间 hwclock --show - 修改硬件时间 hwclock --set --date "2020-07-02 23:49:40" - 同步系统时间和硬件时间 hwclock --hctosys - 保存时钟 clock -w - 重启系统

操作过程
安装 OpenVPN 包
#临时关闭selinux
setenforce 0
#配置文件永久关闭 修改/etc/selinux/config 文件
SELINUX=disabled

#添加epel yum源
wget -O /etc/yum.repos.d/epel-7.repo http://mirrors.aliyun.com/repo/epel-7.repo

#yum安装包
yum install openvpn -y
配置EasyRSA
#下载EasyRSA 3.0.7
cd /opt/
wget https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.7/EasyRSA-3.0.7.tgz
tar xf EasyRSA-3.0.7.tgz
mv EsyRSA-3.0.7 easyRSA-3.0.7
cp -r easyRSA-3.0.7/ /etc/openvpn/easy-rsa3
cp /etc/openvpn/easy-rsa3/vars.example /etc/openvpn/easy-rsa3/vars
创建相关证书和秘钥
cd /etc/openvpn/easy-rsa3/
#初始化目录
./easyrsa init-pki

#创建根证书
#nopass 参数表示不加密；也可以不加此参数，那就需要输入密码短语
./easyrsa build-ca nopass

#创建服务端秘钥
./easyrsa gen-req server nopass

#给服务端证书签名，这里要输入yes才能完成
./easyrsa sign-req server server

##创建客户端秘钥
./easyrsa gen-req client nopass

#给客户端证书签名，这里要输入yes才能完成
./easyrsa sign-req client client

#创建Diffie-Hellman
./easyrsa gen-dh

#创建TLS认证密钥
openvpn --genkey --secret /etc/openvpn/ta.key
拷贝证书到目录
#目录自定义，配置文件中要用到
cd /etc/openvpn/easy-rsa3/pki/
cp ca.crt dh.pem /etc/openvpn/
cp private/server.key issued/server.crt /etc/openvpn/server/
cp private/client.key issued/client.crt /etc/openvpn/client/
编辑配置文件
cd /etc/openvpn/
cp /usr/share/doc/openvpn-2.4.8/sample/sample-config-files/server.conf ./
vim server.conf
#监听本机ip地址 
local 0.0.0.0(这里填本机地址)

#监控本机端口号
port 1194

#指定采用的传输协议，可以选择tcp或udp
proto tcp

#指定创建的通信隧道类型，可选tun或tap
dev tun

#指定CA证书的文件路径
ca /etc/openvpn/ca.crt

#指定服务器端的证书文件路径
cert /etc/openvpn/server/server.crt

#指定服务器端的私钥文件路径
key /etc/openvpn/server/server.key

#指定迪菲赫尔曼参数的文件路径
dh /etc/openvpn/dh.pem

#指定虚拟局域网占用的IP地址段和子网掩码，此处配置的服务器自身占用.1的ip地址
server 10.8.0.0 255.255.255.0

#服务器自动给客户端分配IP后，客户端下次连接时，仍然采用上次的IP地址(第一次分配的IP保存在ipp.txt中，下一次分配其中保存的IP)。
ifconfig-pool-persist ipp.txt

#自动推送客户端上的网关及DHCP
push "redirect-gateway def1 bypass-dhcp"

#OpenVPN的DHCP功能为客户端提供指定的 DNS、WINS 等
push "dhcp-option DNS 114.114.114.114"

#允许客户端与客户端相连接，默认情况下客户端只能与服务器相连接
client-to-client

#每10秒ping一次，连接超时时间设为120秒
keepalive 10 120

#开启TLS-auth，使用ta.key防御攻击。服务器端的第二个参数值为0，客户端的为1。
tls-auth /etc/openvpn/ta.key 0

#加密认证算法
cipher AES-256-CBC

#使用lzo压缩的通讯,服务端和客户端都必须配置
comp-lzo

#最大连接用户
max-clients 100 

#定义运行的用户和组
user openvpn
group openvpn

#重启时仍保留一些状态
persist-key
persist-tun

#输出短日志,每分钟刷新一次,以显示当前的客户端
status /var/log/openvpn-status.log

#日志保存路径
log         /var/log/openvpn.log
log-append  /var/log/openvpn.log

#指定日志文件的记录详细级别，可选0-9，等级越高日志内容越详细
verb 4

#相同信息的数量，如果连续出现 20 条相同的信息，将不记录到日志中
mute 20
配置系统转发和开放端口，云服务器记得安全组要开放对应端口
#修改文件目录权限
chown root.openvpn /etc/openvpn/* -R

#/etc/sysctl.conf 配置文件中添加
net.ipv4.ip_forward=1

#生效
sysctl -p 

#iptables
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
iptables -I INPUT -p tcp --dport 1194 -j ACCEPT

#保存规则并重启
service iptables save
systemctl restart iptables
启动 OpenVPN 服务
#启动 OpenVPN 服务
systemctl start openvpn@server

#确认服务进程是否存在
netstat -lntp|grep openvpn
ps -aux|grep openvpn

#这里可能会无法启动报错，最后说解决办法
客户端连接测试
下载客户端 Mac 下载 Tunnelblick_3.8.2_build_5480
把 ca.crt、client.crt、client.key、ta.key 四个文件放到一个统一的目录下 A 下，这四个文件是从服务器拷贝出来的，具体路径参考上面的步骤
在 A 目录新建 client.ovpn 配置文件，内容如下：
#客户端配置文件
client
dev tun
proto tcp
remote 你的服务器ip/域名 1194
resolv-retry infinite
nobind
persist-key
persist-tun
ca ca.crt
cert client.crt
key client.key
ns-cert-type server
tls-auth ta.key 1
cipher AES-256-CBC
auth-nocache
verb 4
用 Tunnelblick 软件打开 client.ovpn 文件，然后点击连接
错误记录
启动失败
在服务端启动 OpenVPN 的时候，启动失败并报错

Job for openvpn@server.service failed because the control process exited with error code. See "systemctl status openvpn@server.service" and "journalctl -xe" for details.
查看状态 systemctl status openvpn@server.service，根据提示重新检查配置 和 iptables

certificate verify failed
这里主要是客户端和服务端的时间不一致造成的，首页此博文最开始就强调了时间的问题，如果时间不一致，需要调整好时间后重新生成证书才可以。

OpenVPN Bad LZO decompression header byte: 69
客户端连接的时候，提示连接成功，但是会报这个错误然后卡住。这个主要是服务得的配置有 comp-lzo adaptive 这一行，客户端配置里没有，所以需要在客户端配置文件 client.ovpn 里加上一行 comp-lzo ，此配置的默认值就是 adaptive

explicit-exit-notify
explicit-exit-notify 1
#此选项开启只能使用udp协议。否则会报错error: --explicit-exit-notify can only be used with