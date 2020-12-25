#!/usr/bin/env bash
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

cd
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

#myipv6=$(ip -6 a | grep inet6 | grep "scope global" | awk '{print $2}' | cut -d'/' -f1)

colorEcho(){
	set +e
	COLOR=$1
	echo -e "\033[${COLOR}${@:2}\033[0m"
}

  modprobe ip_conntrack
  cat > '/etc/sysctl.d/99-sysctl.conf' << EOF
#!!! Do not change these settings unless you know what you are doing !!!
net.ipv4.conf.all.route_localnet=1
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1
net.ipv4.conf.default.forwarding = 1
################################
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1
net.ipv6.conf.lo.forwarding = 1
################################
net.ipv6.conf.all.disable_ipv6 = 0
net.ipv6.conf.default.disable_ipv6 = 0
net.ipv6.conf.lo.disable_ipv6 = 0
################################
net.ipv6.conf.all.accept_ra = 2
net.ipv6.conf.default.accept_ra = 2
################################
net.core.netdev_max_backlog = 100000
net.core.netdev_budget = 50000
net.core.netdev_budget_usecs = 5000
#fs.file-max = 51200
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 67108864
net.core.wmem_default = 67108864
net.core.optmem_max = 65536
net.core.somaxconn = 10000
################################
net.ipv4.icmp_echo_ignore_all = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.all.rp_filter = 0
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syncookies = 0
net.ipv4.tcp_rfc1337 = 0
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.ip_local_port_range = 10000 65001
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192
net.ipv4.tcp_mtu_probing = 0
##############################
net.ipv4.conf.all.arp_ignore = 2
net.ipv4.conf.default.arp_ignore = 2
net.ipv4.conf.all.arp_announce = 2
net.ipv4.conf.default.arp_announce = 2
##############################
net.ipv4.tcp_autocorking = 0
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_max_syn_backlog = 30000
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_ecn = 2
net.ipv4.tcp_ecn_fallback = 1
net.ipv4.tcp_frto = 0
##############################
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
vm.swappiness = 1
vm.overcommit_memory = 1
net.ipv4.neigh.default.gc_thresh3=8192
net.ipv4.neigh.default.gc_thresh2=4096
net.ipv4.neigh.default.gc_thresh1=2048
net.ipv6.neigh.default.gc_thresh3=8192
net.ipv6.neigh.default.gc_thresh2=4096
net.ipv6.neigh.default.gc_thresh1=2048
net.netfilter.nf_conntrack_max = 262144
net.nf_conntrack_max = 262144
EOF
  sysctl --system
  echo madvise > /sys/kernel/mm/transparent_hugepage/enabled
  cat > '/etc/systemd/system.conf' << EOF
[Manager]
#DefaultTimeoutStartSec=90s
DefaultTimeoutStopSec=30s
#DefaultRestartSec=100ms
DefaultLimitCORE=infinity
DefaultLimitNOFILE=51200
DefaultLimitNPROC=51200
EOF
    cat > '/etc/security/limits.conf' << EOF
* soft nofile 51200
* hard nofile 51200
* soft nproc 51200
* hard nproc 51200
EOF
if grep -q "ulimit" /etc/profile
then
  :
else
echo "ulimit -SHn 51200" >> /etc/profile
echo "ulimit -SHu 51200" >> /etc/profile
fi
if grep -q "pam_limits.so" /etc/pam.d/common-session
then
  :
else
echo "session required pam_limits.so" >> /etc/pam.d/common-session
fi
systemctl daemon-reload

#iptables -t nat -I PREROUTING -i br0 -p udp -m udp --dport 53 -j DNAT --to 10.0.0.1

apt-get update && apt-get upgrade -y && apt-get install xz-utils -y
bash -c "$(wget -O- https://raw.githubusercontent.com/trojan-gfw/trojan-quickstart/master/trojan-quickstart.sh)"

apt-get install ipset -y

ipset create cnip hash:net maxelem 4294967295
ipset create lanip hash:net maxelem 4294967295

curl -LO https://github.com/Hackl0us/GeoIP2-CN/raw/release/CN-ip-cidr.txt

while read LINE
do
  ipset add cnip $LINE
  echo $LINE 
done < CN-ip-cidr.txt

ipset add lanip 127.0.0.1/32
ipset add lanip 255.255.255.255/32
ipset add lanip 10.0.0.0/24
ipset add lanip 169.254.0.0/16
ipset add lanip 172.16.0.0/12
ipset add lanip 192.168.0.0/16
ipset add lanip 224.0.0.0/4
ipset add lanip 240.0.0.0/4
ipset add lanip 0.0.0.0/8

apt-get install curl unzip -y
#sudo bash <(curl -L -s https://install.direct/go.sh)

modprobe xt_TPROXY

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

useradd -m -s /sbin/nologin v2ray
mkdir tmp
cd tmp
curl -LO  https://github.com/v2fly/v2ray-core/releases/download/v4.31.0/v2ray-linux-64.zip
unzip v2ray*
cp v2ray /usr/sbin/
cp v2ctl /usr/sbin/
cp *.dat /usr/sbin/
mkdir /etc/v2ray/
cd
rm -rf tmp
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
     "network": "tcp",
     "followRedirect": true
   },
   "sniffing": {
     "enabled": false,
     "destOverride": ["http", "tls"]
   },
      "streamSettings": {
        "sockopt": {
          "tproxy": "tproxy"
        }
      }
   },
 {
   "tag":"transparent_udp",
   "listen": "127.0.0.1",
   "port": 12345,
   "protocol": "dokodemo-door",
   "settings": {
     "network": "udp",
     "followRedirect": true
   },
   "sniffing": {
     "enabled": false,
     "destOverride": ["http", "tls"]
   },
      "streamSettings": {
        "sockopt": {
          "tproxy": "tproxy"
        }
      }
   },
        {
            "listen": "0.0.0.0",
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
          "mark": 2
        }
      }
    },
        {
      "tag": "direct",
      "protocol": "freedom",
      "settings": {},
      "streamSettings": {
        "sockopt": {
          "mark": 2
        }
      }
    },
         {
       "tag": "adblock",
       "protocol" : "blackhole",
       "settings": {},
       "streamSettings": {
         "sockopt": {
           "mark": 2
               }
            }
        }
	],
    "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "inboundTag": [
          "transparent"
        ],
        "port": 53,
        "network": "udp",
        "outboundTag": "adblock"
      },
      {
        "type": "field",
        "inboundTag": [
          "transparent"
        ],
        "port": "444-65535",
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
        "outboundTag": "adblock"
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
  }
}
EOF

  cat > '/etc/systemd/system/v2ray.service' << EOF
[Unit]
Description=V2Ray Service
Documentation=https://www.v2fly.org/
After=network.target nss-lookup.target

[Service]
User=v2ray
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/sbin/v2ray -config /etc/v2ray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=500
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

/usr/sbin/v2ray -test -config /etc/v2ray/config.json
systemctl start v2ray
systemctl status v2ray

# 设置策略路由
ip route add local default dev lo table 100
ip rule add fwmark 1 lookup 100

# 代理局域网设备
iptables -t mangle -N V2RAY

# 绕过Trojan-Go服务器地址
iptables -t mangle -A V2RAY -d $SERVER_IP -j RETURN

# 绕过私有以及中国大陆地址
iptables -t mangle -A V2RAY -m set --match-set lanip dst -j RETURN #内网ip不经过v2ray直接连接，效能更好，且不会导致udp error
iptables -t mangle -A V2RAY -m set --match-set cnip dst -j RETURN #国内ip不经过v2ray直接连接，效能更好，且不会导致udp error

#iptables -t mangle -A V2RAY -j RETURN -m mark --mark 2    # 直连 SO_MARK 为 0xff 的流量(0xff 是 16 进制数，数值上等同与上面V2Ray 配置的 255)，此规则目的是解决v2ray占用大量CPU（https://github.com/v2ray/v2ray-core/issues/2621）

# 未命中上文的规则的包，打上标记
iptables -t mangle -A V2RAY -j TPROXY -p tcp --on-ip 127.0.0.1 --on-port 12345 --tproxy-mark 0x01/0x01
iptables -t mangle -A V2RAY -j TPROXY -p udp -m udp --on-ip 127.0.0.1 --on-port 12345 --tproxy-mark 0x01/0x01
# 从$INTERFACE网卡流入的所有TCP/UDP包，跳转V2RAY链
iptables -t mangle -A PREROUTING -i br0 -j V2RAY

iptables -I INPUT -s 36.110.236.68/16 -j DROP #屏蔽360,非常重要！
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
#!/usr/bin/env bash

ip route add local default dev lo table 100
ip rule add fwmark 1 lookup 100

/usr/bin/ipset -f /etc/ipset.conf restore
/usr/bin/iptables-restore /etc/iptables/iptables.rules

exit 0

EOF

chmod +x /etc/rc.local
