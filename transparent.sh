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

colorEcho ${INFO} "初始化中(initializing)"
 if cat /etc/*release | grep ^NAME | grep -q Ubuntu; then
	dist=ubuntu
 else
	TERM=ansi whiptail --title "OS not SUPPORTED" --infobox "OS NOT SUPPORTED!" 8 78
	exit 1;
 fi

 if ip a | grep ppp0
then
	:
else
sudo pppoeconf
fi

sudo apt-get update
sudo apt-get upgrade -y

cat > '/etc/netplan/router.yaml' << EOF
network:
    renderer: networkd
    ethernets:
        enp1s0:
          dhcp4: no
        enp2s0:
          dhcp4: no
        enp3s0:
          dhcp4: no
        enp4s0:
          dhcp4: no
        enp5s0:
          dhcp4: no
        enp6s0:
          dhcp4: no
    bridges:
      br0:
        addresses: [10.0.0.1/24]
        dhcp4: no
        dhcp6: no
        accept-ra: no
        interfaces:
          - enp6s0
          - enp5s0
          - enp4s0
          - enp3s0
          - enp2s0
    version: 2
EOF

sudo netplan apply
#################################################################
colorEcho ${INFO} "Install BBR ing"

	cat > '/etc/sysctl.d/99-sysctl.conf' << EOF
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
net.core.rmem_default = 65536
net.core.wmem_default = 65536
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
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_tw_recycle = 0
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.ip_local_port_range = 10000 65000
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
net.ipv4.tcp_ecn = 2
net.ipv4.tcp_ecn_fallback = 1
net.ipv4.tcp_frto = 0
net.ipv4.tcp_fack = 0
##############################
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
vm.swappiness = 5
net.ipv4.ip_unprivileged_port_start = 0
EOF
	sysctl --system
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
#################################################################
colorEcho ${INFO} "Install dnscrypt-proxy ing"
dnsver=$(curl -s "https://api.github.com/repos/DNSCrypt/dnscrypt-proxy/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
tar -xvf dnscrypt-proxy-linux_x86_64-${dnsver}.tar.gz
rm dnscrypt-proxy-linux_x86_64-${dnsver}.tar.gz
cd linux-x86_64
cp -f dnscrypt-proxy /usr/sbin/dnscrypt-proxy
chmod +x /usr/sbin/dnscrypt-proxy
cd ..
rm -rf linux-x86_64
setcap CAP_NET_BIND_SERVICE=+eip /usr/sbin/dnscrypt-proxy
wget -P /etc/dnscrypt-proxy/ https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v2/public-resolvers.md -q --show-progress
wget -P /etc/dnscrypt-proxy/ https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v2/opennic.md -q --show-progress
wget -P /etc/dnscrypt-proxy/ https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v2/relays.md -q --show-progress

if [[ -n ${myipv6} ]]; then
	ping -6 ipv6.google.com -c 2 || ping -6 2620:fe::10 -c 2
	if [[ $? -eq 0 ]]; then
		ipv6_true="true"
		block_ipv6="false"
	fi
fi
    cat > '/etc/dnscrypt-proxy/dnscrypt-proxy.toml' << EOF
#Do not change these settings unless you know what you are doing !
listen_addresses = ['127.0.0.1:5353']
user_name = 'nobody'
max_clients = 250
ipv4_servers = true
ipv6_servers = $ipv6_true
dnscrypt_servers = true
doh_servers = true
require_dnssec = false
require_nolog = true
require_nofilter = true
disabled_server_names = ['cisco', 'cisco-ipv6', 'cisco-familyshield']
force_tcp = false
timeout = 5000
keepalive = 30
lb_estimator = true
log_level = 2
use_syslog = true
#log_file = '/var/log/dnscrypt-proxy/dnscrypt-proxy.log'
cert_refresh_delay = 720
tls_disable_session_tickets = true
#tls_cipher_suite = [4865]
fallback_resolvers = ['1.1.1.1:53', '8.8.8.8:53']
ignore_system_dns = true
netprobe_timeout = 60
netprobe_address = '1.1.1.1:53'
# Maximum log files size in MB - Set to 0 for unlimited.
log_files_max_size = 0
# How long to keep backup files, in days
log_files_max_age = 7
# Maximum log files backups to keep (or 0 to keep all backups)
log_files_max_backups = 0
block_ipv6 = false
## Immediately respond to A and AAAA queries for host names without a domain name
block_unqualified = true
## Immediately respond to queries for local zones instead of leaking them to
## upstream resolvers (always causing errors or timeouts).
block_undelegated = true
## TTL for synthetic responses sent when a request has been blocked (due to
## IPv6 or blacklists).
reject_ttl = 600
cache = true
cache_size = 4096
cache_min_ttl = 2400
cache_max_ttl = 86400
cache_neg_min_ttl = 60
cache_neg_max_ttl = 600

#[local_doh]
#
#listen_addresses = ['127.0.0.1:3000']
#path = "/dns-query"
#cert_file = "/etc/trojan/trojan.crt"
#cert_key_file = "/etc/trojan/trojan.key"

[query_log]

  #file = '/var/log/dnscrypt-proxy/query.log'
  format = 'tsv'

[blacklist]

  blacklist_file = '/etc/dnscrypt-proxy/blacklist.txt'

[sources]

  ## An example of a remote source from https://github.com/DNSCrypt/dnscrypt-resolvers

  [sources.'public-resolvers']
  urls = ['https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v2/public-resolvers.md', 'https://download.dnscrypt.info/resolvers-list/v2/public-resolvers.md']
  cache_file = 'public-resolvers.md'
  minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
  prefix = ''

  [sources.'opennic']
  urls = ['https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v2/opennic.md', 'https://download.dnscrypt.info/dnscrypt-resolvers/v2/opennic.md']
  cache_file = 'opennic.md'
  minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
  prefix = ''

  ## Anonymized DNS relays

  [sources.'relays']
  urls = ['https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v2/relays.md', 'https://download.dnscrypt.info/resolvers-list/v2/relays.md']
  cache_file = 'relays.md'
  minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
  refresh_delay = 72
  prefix = ''
EOF

	cat > '/etc/systemd/system/dnscrypt-proxy.service' << EOF
[Unit]
Description=DNSCrypt client proxy
Documentation=https://github.com/DNSCrypt/dnscrypt-proxy/wiki
After=network.target
Before=nss-lookup.target
Wants=nss-lookup.target

[Service]
#User=nobody
NonBlocking=true
ExecStart=/usr/sbin/dnscrypt-proxy -config /etc/dnscrypt-proxy/dnscrypt-proxy.toml
ProtectHome=yes
ProtectControlGroups=yes
ProtectKernelModules=yes
CacheDirectory=dnscrypt-proxy
LogsDirectory=dnscrypt-proxy
RuntimeDirectory=dnscrypt-proxy
LimitNOFILE=51200
LimitNPROC=51200
Restart=on-failure
RestartSec=3s

[Install]
WantedBy=multi-user.target
EOF

	cat > '/etc/dnscrypt-proxy/blacklist.txt' << EOF

###########################
#        Blacklist        #
###########################

## Rules for name-based query blocking, one per line
##
## Example of valid patterns:
##
## ads.*         | matches anything with an "ads." prefix
## *.example.com | matches example.com and all names within that zone such as www.example.com
## example.com   | identical to the above
## =example.com  | block example.com but not *.example.com
## *sex*         | matches any name containing that substring
## ads[0-9]*     | matches "ads" followed by one or more digits
## ads*.example* | *, ? and [] can be used anywhere, but prefixes/suffixes are faster

#ad.*
#ads.*

####Block 360####
#*.cn
*.360.com
*.360jie.com
*.360kan.com
*.360taojin.com
*.i360mall.com
*.qhimg.com
*.qhmsg.com
*.qhres.com
*.qihoo.com
*.nicaifu.com
*.so.com
####Block Xunlei###
*.xunlei.com
####Block Baidu###
*baidu.*
*.bdimg.com
*.bdstatic.com
*.duapps.com
*.quyaoya.com
*.tiebaimg.com
*.xiaodutv.com
*.sina.com
EOF

systemctl daemon-reload
systemctl enable dnscrypt-proxy.service
sudo systemctl stop systemd-resolved
sudo systemctl disable systemd-resolved
systemctl start dnscrypt-proxy.service

iptables -t nat -I PREROUTING -i br0 -p udp -m udp --dport 53 -j DNAT --to 10.0.0.1

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
			"tag": "dns-in",
			"protocol": "dokodemo-door",
			"port": 53,
			"settings": {
				"address": "1.1.1.1",
				"port": 53,
				"network": "udp"
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
#################################################################
colorEcho ${INFO} "安装Qbittorrent(Install Qbittorrent ing)"
add-apt-repository ppa:qbittorrent-team/qbittorrent-stable -y
apt-get update
apt-get install qbittorrent-nox -q -y
#################################################################
colorEcho ${INFO} "Install Nginx ing"
curl -LO --progress-bar https://nginx.org/keys/nginx_signing.key
apt-key add nginx_signing.key
rm -rf nginx_signing.key
touch /etc/apt/sources.list.d/nginx.list
cat > '/etc/apt/sources.list.d/nginx.list' << EOF
deb https://nginx.org/packages/mainline/$dist/ $(lsb_release -cs) nginx
deb-src https://nginx.org/packages/mainline/$dist/ $(lsb_release -cs) nginx
EOF
apt-get update
apt-get install nginx -q -y
systemctl start nginx
#################################################################
colorEcho ${INFO} "Install Aria2 ing"
ariaport=$(shuf -i 10000-19000 -n 1)
#trackers_list=$(wget -qO- https://trackerslist.com/all.txt |awk NF|sed ":a;N;s/\n/,/g;ta")
trackers_list=$(wget -qO- https://trackerslist.com/all_aria2.txt)
cat > '/etc/systemd/system/aria2.service' << EOF
[Unit]
Description=Aria2c download manager
Requires=network.target
After=network.target

[Service]
Type=forking
User=root
RemainAfterExit=yes
ExecStart=/usr/local/bin/aria2c --conf-path=/etc/aria2.conf
ExecReload=/usr/bin/kill -HUP \$MAINPID
ExecStop=/usr/bin/kill -s STOP \$MAINPID
LimitNOFILE=51200
LimitNPROC=51200
RestartSec=3s
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
	cat > '/etc/aria2.conf' << EOF
#Do not change these settings unless you know what you are doing !
#Global Settings###
daemon=true
async-dns=true
#enable-async-dns6=true
log-level=notice
console-log-level=info
human-readable=true
log=/var/log/aria2.log
rlimit-nofile=51200
event-poll=epoll
min-tls-version=TLSv1.1
dir=/usr/share/nginx/aria2/
file-allocation=falloc
check-integrity=true
conditional-get=false
disk-cache=64M #Larger is better,but should be smaller than available RAM !
enable-color=true
continue=true
always-resume=true
max-concurrent-downloads=50
content-disposition-default-utf8=true
#split=16
##Http(s) Settings#######
enable-http-keep-alive=true
http-accept-gzip=true
min-split-size=10M
max-connection-per-server=16
lowest-speed-limit=0
disable-ipv6=false
max-tries=0
#retry-wait=0
input-file=/usr/local/bin/aria2.session
save-session=/usr/local/bin/aria2.session
save-session-interval=60
force-save=true
metalink-preferred-protocol=https
##Rpc Settings############
enable-rpc=true
rpc-allow-origin-all=true
rpc-listen-all=true
rpc-secure=false
rpc-listen-port=6800
rpc-secret=$ariapasswd
#Bittorrent Settings######
follow-torrent=true
listen-port=$ariaport
enable-dht=true
enable-dht6=true
enable-peer-exchange=true
seed-ratio=0
bt-enable-lpd=true
bt-hash-check-seed=true
bt-seed-unverified=false
bt-save-metadata=true
bt-load-saved-metadata=true
bt-require-crypto=true
bt-force-encryption=true
bt-min-crypto-level=arc4
bt-max-peers=0
bt-tracker=$trackers_list
EOF

apt-get install nettle-dev libgmp-dev libssh2-1-dev libc-ares-dev libxml2-dev zlib1g-dev libsqlite3-dev libssl-dev libuv1-dev -q -y
curl -LO --progress-bar https://raw.githubusercontent.com/johnrosen1/trojan-gfw-script/master/binary/aria2c.xz
xz --decompress aria2c.xz
cp -f aria2c /usr/local/bin/aria2c
chmod +x /usr/local/bin/aria2c
rm aria2c
apt-get autoremove -q -y
systemctl daemon-reload
systemctl enable aria2
systemctl start aria2
#################################################################
colorEcho ${INFO} "Install Netdata ing"

bash <(curl -Ss https://my-netdata.io/kickstart-static64.sh) --dont-wait

	cat > '/opt/netdata/etc/netdata/python.d/web_log.conf' << EOF
nginx_log:
  name  : 'nginx_log'
  path  : '/var/log/nginx/access.log'
EOF

sleep 1

wget -O /opt/netdata/etc/netdata/netdata.conf http://localhost:19999/netdata.conf
#################################################################
colorEcho ${INFO} "Install Bittorrent-Tracker ing"
curl -sL https://deb.nodesource.com/setup_13.x | sudo -E bash -
apt-get install -q -y nodejs
useradd -r bt_tracker --shell=/usr/sbin/nologin
npm install -g bittorrent-tracker --quiet
	cat > '/etc/systemd/system/tracker.service' << EOF
[Unit]
Description=Bittorrent-Tracker Daemon Service
Wants=network-online.target
After=network-online.target nss-lookup.target

[Service]
Type=simple
User=bt_tracker
Group=bt_tracker
RemainAfterExit=yes
ExecStart=/usr/bin/bittorrent-tracker --trust-proxy
TimeoutStopSec=infinity
LimitNOFILE=51200
LimitNPROC=51200
Restart=on-failure
RestartSec=3s

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable tracker
systemctl start tracker
#################################################################
colorEcho ${INFO} "Install filebrowser ing"
curl -fsSL https://raw.githubusercontent.com/filebrowser/get/master/get.sh | bash
cat > '/etc/systemd/system/filebrowser.service' << EOF
[Unit]
Description=filebrowser browser
After=network.target

[Service]
User=root
Group=root
RemainAfterExit=yes
ExecStart=/usr/local/bin/filebrowser -r /usr/share/nginx/ -d /etc/filebrowser/database.db -b $filepath -p 8081
ExecReload=/usr/bin/kill -HUP \$MAINPID
ExecStop=/usr/bin/kill -s STOP \$MAINPID
LimitNOFILE=51200
LimitNPROC=51200
RestartSec=3s
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable filebrowser
mkdir /etc/filebrowser/
touch /etc/filebrowser/database.db
chmod -R 755 /etc/filebrowser/