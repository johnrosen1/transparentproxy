#!/bin/bash
#MIT License
#
#Copyright (c) 2019-2020 johnrosen1

#Permission is hereby granted, free of charge, to any person obtaining a copy
#of this software and associated documentation files (the "Software"), to deal
#in the Software without restriction, including without limitation the rights
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#copies of the Software, and to permit persons to whom the Software is
#furnished to do so, subject to the following conditions:

#The above copyright notice and this permission notice shall be included in all
#copies or substantial portions of the Software.

#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#SOFTWARE.

clear

set +e

if [[ $(id -u) != 0 ]]; then
	echo Please run this script as root.
	exit 1
fi

if [[ $(uname -m 2> /dev/null) != x86_64 ]]; then
	echo Please run this script on x86_64 machine.
	exit 1
fi

myipv6=$(ip -6 a | grep inet6 | grep "scope global" | awk '{print $2}' | cut -d'/' -f1)

colorEcho(){
	set +e
	COLOR=$1
	echo -e "\033[${COLOR}${@:2}\033[0m"
}

#iptables -t nat -I PREROUTING -i br0 -p udp -m udp --dport 53 -j DNAT --to 10.0.0.1

sudo apt-get update && sudo apt-get upgrade -y && sudo apt-get install xz-utils -y
sudo bash -c "$(wget -O- https://raw.githubusercontent.com/trojan-gfw/trojan-quickstart/master/trojan-quickstart.sh)"

sudo apt-get install curl unzip -y
sudo bash <(curl -L -s https://install.direct/go.sh)

sudo modprobe xt_TPROXY

echo "xt_TPROXY" > '/etc/modules-load.d/TPROXY.conf'

	cat > '/usr/local/etc/trojan/config.json' << EOF
{
    "run_type": "client",
    "local_addr": "127.0.0.1",
    "local_port": 1080,
    "remote_addr": "1.1.1.1",
    "remote_port": 443,
    "password": [
        "password1"
    ],
    "log_level": 1,
    "ssl": {
        "verify": true,
        "verify_hostname": true,
        "cert": "",
        "cipher": "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:AES128-SHA:AES256-SHA:DES-CBC3-SHA",
        "cipher_tls13": "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
        "sni": "example.com",
        "alpn": [
            "h2",
            "http/1.1"
        ],
        "reuse_session": true,
        "session_ticket": false,
        "curves": ""
    },
    "tcp": {
        "no_delay": true,
        "keep_alive": true,
        "reuse_port": false,
        "fast_open": false,
        "fast_open_qlen": 20
    }
}
EOF

systemctl start trojan
systemctl enable trojan

	cat > '/etc/v2ray/config.json' << EOF
{
	"log": {
    "error": "/etc/v2ray/error.log",
    "access": "/etc/v2ray/access.log",
    "loglevel": "warning"
  	},
	"inbounds": [
 {
   "tag":"transparent",
   "port": 12345,
   "protocol": "dokodemo-door",
   "settings": {
     "network": "tcp,udp",
     "followRedirect": true
   },
   "sniffing": {
     "enabled": true,
     "destOverride": ["http", "tls"]
   },
      "streamSettings": {
        "sockopt": {
          "tproxy": "tproxy"
        }
      }
   },
        {
            "listen": "127.0.0.1",
            "port": 8001,
            "protocol": "http",
            "settings": {
                 "timeout": 0,
                 "allowTransparent": false,
                 "userLevel": 0
                        },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http","tls"]
            }
        }
	],
	"outbounds": [
    {
      "tag": "proxy",
      "protocol": "socks",
      "settings": {
  "servers": [{
    "address": "127.0.0.1",
    "port": 1080
  		}]
	},
      "streamSettings": {
        "sockopt": {
          "mark": 255
        }
      }
    },
        {
      "tag": "direct",
      "protocol": "freedom",
      "settings": {},
      "streamSettings": {
        "sockopt": {
          "mark": 255
        }
      }
    },
         {
       "tag": "adblock",
       "protocol" : "blackhole",
       "settings": {},
       "streamSettings": {
         "sockopt": {
           "mark": 255
               }
            }
        },
    {
      "protocol": "dns",
      "tag": "dns-out"
    }
	],
    "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "inboundTag": ["dns-in"],
        "outboundTag": "dns-out"
      },
      {
        "type": "field",
        "inboundTag": [
          "transparent"
        ],
        "port": 53,
        "network": "udp",
        "outboundTag": "dns-out"
      },
      {
        "type": "field",
        "inboundTag": [
          "transparent"
        ],
        "port": "10000-65535",
        "network": "tcp,udp",
        "outboundTag": "direct"
      },
      {
        "type": "field",
        "inboundtag": [
          "transparent"
       ],
       "port": 123,
       "network": "udp",
       "outboundTag": "direct"
      },
      {
        "type": "field",
        "inboundtag": [
          "transparent"
       ],
       "port": 1723,
       "network": "tcp,udp",
       "outboundTag": "adblock"
      },
      {
        "type": "field",
        "ip": ["223.5.5.5","114.114.114.114"],
        "outboundTag": "direct"
      },
      {
        "type": "field",
        "ip": ["8.8.8.8","1.1.1.1"],
        "outboundTag": "proxy"
      },
      {
        "type": "field",
        "domain": ["geosite:qihoo360"],
        "outboundTag": "adblock"
      },
      {
        "type": "field",
        "ip": ["geoip:private","geoip:cn"],
        "outboundTag": "direct"
      },
      {
        "type": "field",
        "domain": ["geosite:cn"],
        "outboundTag": "direct"
      },
      {
         "type": "field",
         "outboundTag": "direct",
         "protocol": ["bittorrent"]
      }
    ]
  },
    "dns": {
      "hosts": {
    "geosite:qihoo360": "www.johnrosen1.com"
    },
    "servers": [{"address": "127.0.0.1","port": 5353},{"address": "114.114.114.114","port": 53,"domains": ["geosite:cn","bilibili.com","ntp.org"]}]
  }
}
EOF

sudo /usr/bin/v2ray/v2ray -test -config /etc/v2ray/config.json
sudo systemctl start v2ray
sudo systemctl status v2ray

# 设置策略路由
ip rule add fwmark 1 table 100 
ip route add local 0.0.0.0/0 dev lo table 100

# 代理局域网设备
iptables -t mangle -N V2RAY
iptables -t mangle -A V2RAY -d 127.0.0.1/32 -j RETURN
iptables -t mangle -A V2RAY -d 224.0.0.0/4 -j RETURN
iptables -t mangle -A V2RAY -d 255.255.255.255/32 -j RETURN
iptables -t mangle -A V2RAY -d 10.0.0.0/24 -j RETURN
iptables -t mangle -A V2RAY -d 192.168.0.0/16 -j RETURN # 直连局域网，避免 V2Ray 无法启动时无法连网关的 SSH，如果你配置的是其他网段（如 10.x.x.x 等），则修改成自己的
iptables -t mangle -A V2RAY -p udp -j TPROXY --on-port 12345 --tproxy-mark 1 # 给 UDP 打标记 1，转发至 12345 端口
iptables -t mangle -A V2RAY -p tcp -j TPROXY --on-port 12345 --tproxy-mark 1 # 给 TCP 打标记 1，转发至 12345 端口
iptables -t mangle -A PREROUTING -j V2RAY # 应用规则

iptables -I INPUT -s 36.110.236.68/16 -j DROP
iptables -I FORWARD -d 36.110.236.68/16 -j DROP
iptables -I OUTPUT -d 36.110.236.68/16 -j DROP

cat > '/lib/systemd/system/rc-local.service' << EOF
#  SPDX-License-Identifier: LGPL-2.1+
#
#  This file is part of systemd.
#
#  systemd is free software; you can redistribute it and/or modify it
#  under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation; either version 2.1 of the License, or
#  (at your option) any later version.

# This unit gets pulled automatically into multi-user.target by
# systemd-rc-local-generator if /etc/rc.local is executable.
[Unit]
Description=/etc/rc.local Compatibility
Documentation=man:systemd-rc-local-generator(8)
ConditionFileIsExecutable=/etc/rc.local
After=network.target

[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
RemainAfterExit=yes
GuessMainPID=no

[Install]
 WantedBy=multi-user.target
EOF

systemctl enable rc-local

cat > '/etc/rc.local' << EOF
#!/bin/bash

# 设置策略路由
ip rule add fwmark 1 table 100 
ip route add local 0.0.0.0/0 dev lo table 100

iptables -t nat -I PREROUTING -i br-lan -p udp --dport 53 -j DNAT --to 10.0.0.1
iptables -t nat -I PREROUTING -i br-lan -p udp --dport 53 -j DNAT --to 10.0.0.1

iptables -I INPUT -s 36.110.236.68/16 -j DROP
iptables -I FORWARD -d 36.110.236.68/16 -j DROP
iptables -I OUTPUT -d 36.110.236.68/16 -j DROP

# 代理局域网设备
iptables -t mangle -N V2RAY
iptables -t mangle -A V2RAY -d 127.0.0.1/32 -j RETURN
iptables -t mangle -A V2RAY -d 224.0.0.0/4 -j RETURN
iptables -t mangle -A V2RAY -d 255.255.255.255/32 -j RETURN
iptables -t mangle -A V2RAY -d 10.0.0.0/24 -j RETURN
iptables -t mangle -A V2RAY -d 192.168.0.0/16 -j RETURN # 直连局域网，避免 V2Ray 无法启动时无法连网关的 SSH，如果你配置的是其他网段（如 10.x.x.x 等），则修改成自己的
iptables -t mangle -A V2RAY -p udp -j TPROXY --on-port 12345 --tproxy-mark 1 # 给 UDP 打标记 1，转发至 12345 端口
iptables -t mangle -A V2RAY -p tcp -j TPROXY --on-port 12345 --tproxy-mark 1 # 给 TCP 打标记 1，转发至 12345 端口
iptables -t mangle -A PREROUTING -j V2RAY # 应用规则

exit 0

EOF
