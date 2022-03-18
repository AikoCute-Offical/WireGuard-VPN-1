#!/bin/bash
#
# https://github.com/Nyr/wireguard-install
#
# Bản quyền (c) Nyr 2020. Được phát hành theo Giấy phép MIT.

# Phát hiện người dùng Debian chạy kịch bản với "sh" thay vì bash
if readlink /proc/$$/exe | grep -q "dash"; then
	Echo "Trình cài đặt này cần phải được chạy với "bash", không phải "sh"."
	exit
fi

# Loại bỏ stdin. Cần thiết khi chạy từ một lớp lót bao gồm một dòng mới
read -N 999999 -t 0.001

# Detect OpenVZ 6
if [[ $(uname -r | cut -d "." -f 1) -eq 2 ]]; then
	echo "Hệ thống đang chạy một hạt nhân cũ, không tương thích với trình cài đặt này."
	exit
fi

# Detect OS
# $os_version không phải lúc nào cũng được sử dụng, nhưng được giữ ở đây để thuận tiện
if grep -qs "ubuntu" /etc/os-release; then
	os="ubuntu"
	os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
elif [[ -e /etc/debian_version ]]; then
	os="debian"
	os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
elif [[ -e /etc/almalinux-release || -e /etc/rocky-release || -e /etc/centos-release ]]; then
	os="centos"
	os_version=$(grep -shoE '[0-9]+' /etc/almalinux-release /etc/rocky-release /etc/centos-release | head -1)
elif [[ -e /etc/fedora-release ]]; then
	os="fedora"
	os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
else
	echo "Trình cài đặt này dường như đang chạy trên một phân phối không được hỗ trợ.
Các bản phân phối được hỗ trợ là Ubuntu, Debian, AlmaLinux, Rocky Linux, CentOS và Fedora."
	exit
fi

if [[ "$os" == "ubuntu" && "$os_version" -lt 1804 ]]; then
	echo "Ubuntu 18.04 trở lên được yêu cầu sử dụng trình cài đặt này.
Phiên bản Ubuntu này quá cũ và không được hỗ trợ."
	exit
fi

if [[ "$os" == "debian" && "$os_version" -lt 10 ]]; then
	echo "Debian 10 hoặc cao hơn là cần thiết để sử dụng trình cài đặt này.
Phiên bản này của Debian quá cũ và không được hỗ trợ."
	exit
fi

if [[ "$os" == "centos" && "$os_version" -lt 7 ]]; then
	echo "CentOS 7 or higher is required to use this installer.
This version of CentOS is too old and unsupported."
	exit
fi

# Phát hiện môi trường mà $PATH không bao gồm các thư mục sbin
if ! grep -q sbin <<< "$PATH"; then
	echo '$PATH không bao gồm sbin. Hãy thử sử dụng "su -" thay vì "su".'
	exit
fi

systemd-detect-virt -cq
is_container="$?"

if [[ "$os" == "fedora" && "$os_version" -eq 31 && $(uname -r | cut -d "." -f 2) -lt 6 && ! "$is_container" -eq 0 ]]; then
	echo 'Fedora 31 được hỗ trợ, nhưng hạt nhân đã lỗi thời.
Nâng cấp kernel bằng cách sử dụng "dnf upgrade kernel" và khởi động lại.'
	exit
fi

if [[ "$EUID" -ne 0 ]]; then
	echo "Trình cài đặt này cần phải được chạy với các đặc quyền superuser."
	exit
fi

if [[ "$is_container" -eq 0 ]]; then
	if [ "$(uname -m)" != "x86_64" ]; then
		echo "Trong các hệ thống container, trình cài đặt này chỉ hỗ trợ kiến trúc x86_64.
Hệ thống chạy trên $(uname -m) và không được hỗ trợ."
		exit
	fi
	# TUN device is required to use BoringTun if running inside a container
	if [[ ! -e /dev/net/tun ]] || ! ( exec 7<>/dev/net/tun ) 2>/dev/null; then
		echo "Hệ thống không có sẵn thiết bị TUN.
TUN cần được kích hoạt trước khi chạy trình cài đặt này."
		exit
	fi
fi

new_client_dns () {
	echo "Chọn máy chủ DNS cho máy khách:"
	echo "   1) Current system resolvers"
	echo "   2) Google"
	echo "   3) 1.1.1.1"
	echo "   4) OpenDNS"
	echo "   5) Quad9"
	echo "   6) AdGuard"
	read -p "DNS server [1]: " dns
	until [[ -z "$dns" || "$dns" =~ ^[1-6]$ ]]; do
		echo "$dns: invalid selection."
		read -p "DNS server [1]: " dns
	done
		# DNS
	case "$dns" in
		1|"")
			# Xác định vị trí giải quyết thích hợp.conf
			# Cần thiết cho các hệ thống chạy được giải quyết theo hệ thống
			if grep -q '^nameserver 127.0.0.53' "/etc/resolv.conf"; then
				resolv_conf="/run/systemd/resolve/resolv.conf"
			else
				resolv_conf="/etc/resolv.conf"
			fi
			# Trích xuất máy chủ tên và cung cấp chúng ở định dạng cần thiết
			dns=$(grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | xargs | sed -e 's/ /, /g')
		;;
		2)
			dns="8.8.8.8, 8.8.4.4"
		;;
		3)
			dns="1.1.1.1, 1.0.0.1"
		;;
		4)
			dns="208.67.222.222, 208.67.220.220"
		;;
		5)
			dns="9.9.9.9, 149.112.112.112"
		;;
		6)
			dns="94.140.14.14, 94.140.15.15"
		;;
	esac
}

new_client_setup () {
	# Với danh sách các địa chỉ IPv4 nội bộ được chỉ định, có được mức thấp nhất vẫn còn
	# octet có sẵn. Điều quan trọng là bắt đầu nhìn vào 2, bởi vì 1 là cửa ngõ của chúng tôi.
	octet=2
	while grep AllowedIPs /etc/wireguard/wg0.conf | cut -d "." -f 4 | cut -d "/" -f 1 | grep -q "$octet"; do
		(( octet++ ))
	done
	# Không phá vỡ cấu hình WireGuard trong trường hợp không gian địa chỉ đầy
	if [[ "$octet" -eq 255 ]]; then
		echo "253 khách hàng đã được cấu hình. Mạng con nội bộ WireGuard đã đầy!"
		exit
	fi
	key=$(wg genkey)
	psk=$(wg genpsk)
	# Configure client in the server
	cat << EOF >> /etc/wireguard/wg0.conf
# BEGIN_PEER $client
[Peer]
PublicKey = $(wg pubkey <<< $key)
PresharedKey = $psk
AllowedIPs = 10.7.0.$octet/32$(grep -q 'fddd:2c4:2c4:2c4::1' /etc/wireguard/wg0.conf && echo ", fddd:2c4:2c4:2c4::$octet/128")
# END_PEER $client
EOF
	# Create client configuration
	cat << EOF > ~/"$client".conf
[Interface]
Address = 10.7.0.$octet/24$(grep -q 'fddd:2c4:2c4:2c4::1' /etc/wireguard/wg0.conf && echo ", fddd:2c4:2c4:2c4::$octet/64")
DNS = $dns
PrivateKey = $key

[Peer]
PublicKey = $(grep PrivateKey /etc/wireguard/wg0.conf | cut -d " " -f 3 | wg pubkey)
PresharedKey = $psk
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = $(grep '^# ENDPOINT' /etc/wireguard/wg0.conf | cut -d " " -f 3):$(grep ListenPort /etc/wireguard/wg0.conf | cut -d " " -f 3)
PersistentKeepalive = 25
EOF
}

if [[ ! -e /etc/wireguard/wg0.conf ]]; then
	# Phát hiện một số thiết lập tối thiểu Debian nơi không wget hoặc curl được cài đặt
	if ! hash wget 2>/dev/null && ! hash curl 2>/dev/null; then
		echo "Wget được yêu cầu sử dụng trình cài đặt này."
		read -n1 -r -p "Nhấn bất kỳ phím nào để cài đặt Wget và tiếp tục..."
		apt-get update
		apt-get install -y wget
	fi
	clear
	echo 'Chào mừng bạn đến với trình cài đặt chiến binh đường WireGuard này!'
	# Nếu hệ thống có một IPv4 duy nhất, nó sẽ được chọn tự động. Nếu không, hãy hỏi người dùng
	if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
	else
		number_of_ip=$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}')
		echo
		echo "Nên sử dụng địa chỉ IPv4 nào?"
		ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
		read -p "IPv4 address [1]: " ip_number
		until [[ -z "$ip_number" || "$ip_number" =~ ^[0-9]+$ && "$ip_number" -le "$number_of_ip" ]]; do
			echo "$ip_number: invalid selection."
			read -p "IPv4 address [1]: " ip_number
		done
		[[ -z "$ip_number" ]] && ip_number="1"
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "$ip_number"p)
	fi
	# Nếu $ip là địa chỉ IP riêng tư, máy chủ phải đứng sau NAT
	if echo "$ip" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		echo
		echo "Máy chủ này đứng sau NAT. Địa chỉ IPv4 công cộng hoặc tên máy chủ là gì?"
		# Nhận IP công cộng và vệ sinh bằng grep
		get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" || curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")")
		read -p "Public IPv4 address / hostname [$get_public_ip]: " public_ip
		# Nếu dịch vụ checkip không khả dụng và người dùng không cung cấp đầu vào, hãy hỏi lại
		until [[ -n "$get_public_ip" || -n "$public_ip" ]]; do
			echo "Invalid input."
			read -p "Public IPv4 address / hostname: " public_ip
		done
		[[ -z "$public_ip" ]] && public_ip="$get_public_ip"
	fi
	# Nếu hệ thống có một IPv6 duy nhất, nó sẽ được chọn tự động
	if [[ $(ip -6 addr | grep -c 'inet6 [23]') -eq 1 ]]; then
		ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}')
	fi
	# Nếu hệ thống có nhiều IPv6, hãy yêu cầu người dùng chọn một
	if [[ $(ip -6 addr | grep -c 'inet6 [23]') -gt 1 ]]; then
		number_of_ip6=$(ip -6 addr | grep -c 'inet6 [23]')
		echo
		echo "Nên sử dụng địa chỉ IPv6 nào?"
		ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | nl -s ') '
		read -p "IPv6 address [1]: " ip6_number
		until [[ -z "$ip6_number" || "$ip6_number" =~ ^[0-9]+$ && "$ip6_number" -le "$number_of_ip6" ]]; do
			echo "$ip6_number: invalid selection."
			read -p "IPv6 address [1]: " ip6_number
		done
		[[ -z "$ip6_number" ]] && ip6_number="1"
		ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | sed -n "$ip6_number"p)
	fi
	echo
	echo "WireGuard nên nghe cổng nào?"
	read -p "Port [51820]: " port
	until [[ -z "$port" || "$port" =~ ^[0-9]+$ && "$port" -le 65535 ]]; do
		echo "$port: invalid port."
		read -p "Port [51820]: " port
	done
	[[ -z "$port" ]] && port="51820"
	echo
	echo "Enter a name for the first client:"
	read -p "Name [client]: " unsanitized_client
	# Cho phép một tập hợp các ký tự giới hạn để tránh xung đột
	client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
	[[ -z "$client" ]] && client="client"
	echo
	new_client_dns
	# Thiết lập cập nhật tự động cho BoringTun nếu người dùng ổn với điều đó
	if [[ "$is_container" -eq 0 ]]; then
		echo
		echo "BoringTun sẽ được cài đặt để thiết lập WireGuard trong hệ thống."
		read -p "Có nên bật cập nhật tự động cho nó không? [Y/n]: " boringtun_updates
		until [[ "$boringtun_updates" =~ ^[yYnN]*$ ]]; do
			echo "$remove: invalid selection."
			read -p "Có nên bật cập nhật tự động cho nó không? [Y/n]: " boringtun_updates
		done
		[[ -z "$boringtun_updates" ]] && boringtun_updates="y"
		if [[ "$boringtun_updates" =~ ^[yY]$ ]]; then
			if [[ "$os" == "centos" || "$os" == "fedora" ]]; then
				cron="cronie"
			elif [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
				cron="cron"
			fi
		fi
	fi
	echo
	echo "Cài đặt WireGuard đã sẵn sàng để bắt đầu."
	# Cài đặt tường lửa nếu tường lửa hoặc iptable chưa sẵn dùng
	if ! systemctl is-active --quiet firewalld.service && ! hash iptables 2>/dev/null; then
		if [[ "$os" == "centos" || "$os" == "fedora" ]]; then
			firewall="firewalld"
			# Chúng tôi không muốn âm thầm bật tường lửa, vì vậy chúng tôi đưa ra một cảnh báo tinh tế
			# Nếu người dùng tiếp tục, tường lửa sẽ được cài đặt và bật trong quá trình thiết lập
			echo "tường lửa, được yêu cầu để quản lý bảng định tuyến, cũng sẽ được cài đặt."
		elif [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
			# iptables ít xâm lấn hơn tường lửa vì vậy không có cảnh báo nào được đưa ra
			firewall="iptables"
		fi
	fi
	read -n1 -r -p "Nhấn phím nào để tiếp tục..."
	# Cài đặt WireGuard
	# Nếu không chạy bên trong thùng chứa, hãy thiết lập mô-đun hạt nhân WireGuard
	if [[ ! "$is_container" -eq 0 ]]; then
		if [[ "$os" == "ubuntu" ]]; then
			# Ubuntu
			apt-get update
			apt-get install -y wireguard qrencode $firewall
		elif [[ "$os" == "debian" && "$os_version" -ge 11 ]]; then
			# Debian 11 or higher
			apt-get update
			apt-get install -y wireguard qrencode $firewall
		elif [[ "$os" == "debian" && "$os_version" -eq 10 ]]; then
			# Debian 10
			if ! grep -qs '^deb .* buster-backports main' /etc/apt/sources.list /etc/apt/sources.list.d/*.list; then
				echo "deb http://deb.debian.org/debian buster-backports main" >> /etc/apt/sources.list
			fi
			apt-get update
			# Cố gắng cài đặt tiêu đề hạt nhân cho nhân đang chạy và tránh khởi động lại. Này
			# có thể thất bại, vì vậy điều quan trọng là phải chạy riêng biệt với lệnh apt-get khác.
			apt-get install -y linux-headers-"$(uname -r)"
			# Có nhiều cách sạch hơn để tìm ra $architecture, nhưng chúng tôi yêu cầu một
			# định dạng cụ thể cho tên gói và cách tiếp cận này cung cấp những gì chúng ta cần.
			architecture=$(dpkg --get-selections 'linux-image-*-*' | cut -f 1 | grep -oE '[^-]*$' -m 1)
			# linux-headers-$architecture chỉ ra các tiêu đề mới nhất. Chúng tôi cài đặt nó
			# bởi vì nếu hệ thống có một hạt nhân lỗi thời, không có gì đảm bảo rằng cũ
			# tiêu đề vẫn có thể tải xuống và để cung cấp tiêu đề phù hợp cho tương lai
			# cập nhật hạt nhân.
			apt-get install -y linux-headers-"$architecture"
			apt-get install -y wireguard qrencode $firewall
		elif [[ "$os" == "centos" && "$os_version" -eq 8 ]]; then
			# CentOS 8
			dnf install -y epel-release elrepo-release
			dnf install -y kmod-wireguard wireguard-tools qrencode $firewall
			mkdir -p /etc/wireguard/
		elif [[ "$os" == "centos" && "$os_version" -eq 7 ]]; then
			# CentOS 7
			yum install -y epel-release https://www.elrepo.org/elrepo-release-7.el7.elrepo.noarch.rpm
			yum install -y yum-plugin-elrepo
			yum install -y kmod-wireguard wireguard-tools qrencode $firewall
			mkdir -p /etc/wireguard/
		elif [[ "$os" == "fedora" ]]; then
			# Fedora
			dnf install -y wireguard-tools qrencode $firewall
			mkdir -p /etc/wireguard/
		fi
	# Nếu không, chúng ta đang ở trong một container và BoringTun cần phải được sử dụng
	else
		# Cài đặt các gói cần thiết
		if [[ "$os" == "ubuntu" ]]; then
			# Ubuntu
			apt-get update
			apt-get install -y qrencode ca-certificates $cron $firewall
			apt-get install -y wireguard-tools --no-install-recommends
		elif [[ "$os" == "debian" && "$os_version" -ge 11 ]]; then
			# Debian 11 or higher
			apt-get update
			apt-get install -y qrencode ca-certificates $cron $firewall
			apt-get install -y wireguard-tools --no-install-recommends
		elif [[ "$os" == "debian" && "$os_version" -eq 10 ]]; then
			# Debian 10
			if ! grep -qs '^deb .* buster-backports main' /etc/apt/sources.list /etc/apt/sources.list.d/*.list; then
				echo "deb http://deb.debian.org/debian buster-backports main" >> /etc/apt/sources.list
			fi
			apt-get update
			apt-get install -y qrencode ca-certificates $cron $firewall
			apt-get install -y wireguard-tools --no-install-recommends
		elif [[ "$os" == "centos" && "$os_version" -eq 8 ]]; then
			# CentOS 8
			dnf install -y epel-release
			dnf install -y wireguard-tools qrencode ca-certificates tar $cron $firewall
			mkdir -p /etc/wireguard/
		elif [[ "$os" == "centos" && "$os_version" -eq 7 ]]; then
			# CentOS 7
			yum install -y epel-release
			yum install -y wireguard-tools qrencode ca-certificates tar $cron $firewall
			mkdir -p /etc/wireguard/
		elif [[ "$os" == "fedora" ]]; then
			# Fedora
			dnf install -y wireguard-tools qrencode ca-certificates tar $cron $firewall
			mkdir -p /etc/wireguard/
		fi
		# Lấy nhị phân BoringTun bằng cách sử dụng wget hoặc cuộn tròn và chiết xuất vào đúng nơi.
		# Không sử dụng dịch vụ này ở nơi khác mà không có sự cho phép! Hãy liên hệ với tôi trước khi bạn làm!
		{ wget -qO- https://wg.nyr.be/1/latest/download 2>/dev/null || curl -sL https://wg.nyr.be/1/latest/download ; } | tar xz -C /usr/local/sbin/ --wildcards 'boringtun-*/boringtun' --strip-components 1
		# Cấu hình wg-quick để sử dụng BoringTun
		mkdir /etc/systemd/system/wg-quick@wg0.service.d/ 2>/dev/null
		echo "[Service]
Environment=WG_QUICK_USERSPACE_IMPLEMENTATION=boringtun
Environment=WG_SUDO=1" > /etc/systemd/system/wg-quick@wg0.service.d/boringtun.conf
		if [[ -n "$cron" ]] && [[ "$os" == "centos" || "$os" == "fedora" ]]; then
			systemctl enable --now crond.service
		fi
	fi
	# Nếu tường lửa vừa được cài đặt, hãy bật tường lửa
	if [[ "$firewall" == "firewalld" ]]; then
		systemctl enable --now firewalld.service
	fi
	# Tạo wg0.conf
	cat << EOF > /etc/wireguard/wg0.conf
# Do not alter the commented lines
# They are used by wireguard-install
# ENDPOINT $([[ -n "$public_ip" ]] && echo "$public_ip" || echo "$ip")

[Interface]
Address = 10.7.0.1/24$([[ -n "$ip6" ]] && echo ", fddd:2c4:2c4:2c4::1/64")
PrivateKey = $(wg genkey)
ListenPort = $port

EOF
	chmod 600 /etc/wireguard/wg0.conf
	# Bật net.ipv4.ip_forward cho hệ thống
	echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-wireguard-forward.conf
	# Bật mà không cần chờ khởi động lại hoặc khởi động lại dịch vụ
	echo 1 > /proc/sys/net/ipv4/ip_forward
	if [[ -n "$ip6" ]]; then
		# Bật net.ipv6.conf.all.forwarding cho hệ thống
		echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-wireguard-forward.conf
		# Bật mà không cần chờ khởi động lại hoặc khởi động lại dịch vụ
		echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
	fi
	if systemctl is-active --quiet firewalld.service; then
		# Sử dụng cả quy tắc vĩnh viễn và không vĩnh viễn để tránh tường lửa
		# Chạy lại.
		firewall-cmd --add-port="$port"/udp
		firewall-cmd --zone=trusted --add-source=10.7.0.0/24
		firewall-cmd --permanent --add-port="$port"/udp
		firewall-cmd --permanent --zone=trusted --add-source=10.7.0.0/24
		# Đặt NAT cho mạng con VPN
		firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j SNAT --to "$ip"
		firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j SNAT --to "$ip"
		if [[ -n "$ip6" ]]; then
			firewall-cmd --zone=trusted --add-source=fddd:2c4:2c4:2c4::/64
			firewall-cmd --permanent --zone=trusted --add-source=fddd:2c4:2c4:2c4::/64
			firewall-cmd --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j SNAT --to "$ip6"
			firewall-cmd --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j SNAT --to "$ip6"
		fi
	else
		# Tạo một dịch vụ để thiết lập các quy tắc iptables liên tục
		iptables_path=$(command -v iptables)
		ip6tables_path=$(command -v ip6tables)
		# nf_tables không có sẵn như là tiêu chuẩn trong hạt nhân OVZ. Vì vậy, sử dụng iptables-legacy
		# nếu chúng ta đang ở trong OVZ, với một nf_tables backend và iptables-legacy có sẵn.
		if [[ $(systemd-detect-virt) == "openvz" ]] && readlink -f "$(command -v iptables)" | grep -q "nft" && hash iptables-legacy 2>/dev/null; then
			iptables_path=$(command -v iptables-legacy)
			ip6tables_path=$(command -v ip6tables-legacy)
		fi
		echo "[Unit]
Before=network.target
[Service]
Type=oneshot
ExecStart=$iptables_path -t nat -A POSTROUTING -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j SNAT --to $ip
ExecStart=$iptables_path -I INPUT -p udp --dport $port -j ACCEPT
ExecStart=$iptables_path -I FORWARD -s 10.7.0.0/24 -j ACCEPT
ExecStart=$iptables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -t nat -D POSTROUTING -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j SNAT --to $ip
ExecStop=$iptables_path -D INPUT -p udp --dport $port -j ACCEPT
ExecStop=$iptables_path -D FORWARD -s 10.7.0.0/24 -j ACCEPT
ExecStop=$iptables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" > /etc/systemd/system/wg-iptables.service
		if [[ -n "$ip6" ]]; then
			echo "ExecStart=$ip6tables_path -t nat -A POSTROUTING -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j SNAT --to $ip6
ExecStart=$ip6tables_path -I FORWARD -s fddd:2c4:2c4:2c4::/64 -j ACCEPT
ExecStart=$ip6tables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$ip6tables_path -t nat -D POSTROUTING -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j SNAT --to $ip6
ExecStop=$ip6tables_path -D FORWARD -s fddd:2c4:2c4:2c4::/64 -j ACCEPT
ExecStop=$ip6tables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" >> /etc/systemd/system/wg-iptables.service
		fi
		echo "RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" >> /etc/systemd/system/wg-iptables.service
		systemctl enable --now wg-iptables.service
	fi
	# Tạo client.conf tùy chỉnh
	new_client_setup
	# Bật và khởi động dịch vụ wg-quick
	systemctl enable --now wg-quick@wg0.service
	# Thiết lập cập nhật tự động cho BoringTun nếu người dùng muốn
	if [[ "$boringtun_updates" =~ ^[yY]$ ]]; then
		# Deploy upgrade script
		cat << 'EOF' > /usr/local/sbin/boringtun-upgrade
#!/bin/bash
latest=$(wget -qO- https://wg.nyr.be/1/latest 2>/dev/null || curl -sL https://wg.nyr.be/1/latest 2>/dev/null)
# If server did not provide an appropriate response, exit
if ! head -1 <<< "$latest" | grep -qiE "^boringtun.+[0-9]+\.[0-9]+.*$"; then
	echo "Update server unavailable"
	exit
fi
current=$(/usr/local/sbin/boringtun -V)
if [[ "$current" != "$latest" ]]; then
	download="https://wg.nyr.be/1/latest/download"
	xdir=$(mktemp -d)
	# If download and extraction are successful, upgrade the boringtun binary
	if { wget -qO- "$download" 2>/dev/null || curl -sL "$download" ; } | tar xz -C "$xdir" --wildcards "boringtun-*/boringtun" --strip-components 1; then
		systemctl stop wg-quick@wg0.service
		rm -f /usr/local/sbin/boringtun
		mv "$xdir"/boringtun /usr/local/sbin/boringtun
		systemctl start wg-quick@wg0.service
		echo "Succesfully updated to $(/usr/local/sbin/boringtun -V)"
	else
		echo "boringtun update failed"
	fi
	rm -rf "$xdir"
else
	echo "$current is up to date"
fi
EOF
		chmod +x /usr/local/sbin/boringtun-upgrade
		# Thêm công việc cron để chạy trình cập nhật hàng ngày vào một thời điểm ngẫu nhiên từ 3:00 đến 5:59
		{ crontab -l 2>/dev/null; echo "$(( $RANDOM % 60 )) $(( $RANDOM % 3 + 3 )) * * * /usr/local/sbin/boringtun-upgrade &>/dev/null" ; } | crontab -
	fi
	echo
	qrencode -t UTF8 < ~/"$client.conf"
	echo -e '\xE2\x86\x91 That is a QR code containing the client configuration.'
	echo
	# Nếu mô-đun hạt nhân không tải, hệ thống có thể đã có một hạt nhân lỗi thời
	# Chúng tôi sẽ cố gắng giúp đỡ, nhưng sẽ không buộc phải nâng cấp hạt nhân khi người dùng
	if [[ ! "$is_container" -eq 0 ]] && ! modprobe -nq wireguard; then
		echo "Warning!"
		echo "Việc cài đặt đã hoàn tất, nhưng mô-đun hạt nhân WireGuard không thể tải."
		if [[ "$os" == "ubuntu" && "$os_version" -eq 1804 ]]; then
		echo 'Nâng cấp kernel và tiêu đề với "apt-get install linux-generic" và khởi động lại.'
		elif [[ "$os" == "debian" && "$os_version" -eq 10 ]]; then
		echo "Nâng cấp kernel với \"apt-get install linux-image-$architecture\" và khởi động lại."
		elif [[ "$os" == "centos" && "$os_version" -le 8 ]]; then
			echo "Reboot the system to load the most recent kernel."
		fi
	else
		echo "Đã kết thúc!"
	fi
	echo
	echo "Cấu hình máy khách có sẵn trong:" ~/"$client.conf"
	echo "Khách hàng mới có thể được thêm vào bằng cách chạy lại kịch bản này."
else
	clear
	echo "WireGuard đã được cài đặt."
	echo
	echo "Chọn một tùy chọn:"
	echo "1) Thêm một khách hàng mới"
	echo "2) Loại bỏ một khách hàng hiện có"
	echo "3) Loại bỏ WireGuard"
	echo "4) Exit"
	read -p "Option: " option
	until [[ "$option" =~ ^[1-4]$ ]]; do
		echo "$option: invalid selection."
		read -p "Option: " option
	done
	case "$option" in
		1)
			echo
			echo "Provide a name for the client:"
			read -p "Name: " unsanitized_client
			# Cho phép một tập hợp các ký tự giới hạn để tránh xung đột
			client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
			while [[ -z "$client" ]] || grep -q "^# BEGIN_PEER $client$" /etc/wireguard/wg0.conf; do
				echo "$client: invalid name."
				read -p "Name: " unsanitized_client
				client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
			done
			echo
			new_client_dns
			new_client_setup
			# Thêm cấu hình máy khách mới vào giao diện WireGuard
			wg addconf wg0 <(sed -n "/^# BEGIN_PEER $client/,/^# END_PEER $client/p" /etc/wireguard/wg0.conf)
			echo
			qrencode -t UTF8 < ~/"$client.conf"
			echo -e '\xE2\x86\x91 That is a QR code containing your client configuration.'
			echo
			echo "$client added. Configuration available in:" ~/"$client.conf"
			exit
		;;
		2)
			# Tùy chọn này có thể được ghi lại tốt hơn một chút và thậm chí có thể được đơn giản hóa
			# ... Nhưng tôi có thể nói gì, tôi cũng muốn ngủ một chút
			number_of_clients=$(grep -c '^# BEGIN_PEER' /etc/wireguard/wg0.conf)
			if [[ "$number_of_clients" = 0 ]]; then
				echo
				echo "Không có khách hàng hiện tại!"
				exit
			fi
			echo
			echo "Chọn máy khách để loại bỏ:"
			grep '^# BEGIN_PEER' /etc/wireguard/wg0.conf | cut -d ' ' -f 3 | nl -s ') '
			read -p "Client: " client_number
			until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -le "$number_of_clients" ]]; do
				echo "$client_number: invalid selection."
				read -p "Client: " client_number
			done
			client=$(grep '^# BEGIN_PEER' /etc/wireguard/wg0.conf | cut -d ' ' -f 3 | sed -n "$client_number"p)
			echo
			read -p "Confirm $client removal? [y/N]: " remove
			until [[ "$remove" =~ ^[yYnN]*$ ]]; do
				echo "$remove: invalid selection."
				read -p "Confirm $client removal? [y/N]: " remove
			done
			if [[ "$remove" =~ ^[yY]$ ]]; then
				# Sau đây là cách đúng đắn để tránh làm gián đoạn các kết nối hoạt động khác:
				# Loại bỏ khỏi giao diện trực tiếp
				wg set wg0 peer "$(sed -n "/^# BEGIN_PEER $client$/,\$p" /etc/wireguard/wg0.conf | grep -m 1 PublicKey | cut -d " " -f 3)" remove
				# Loại bỏ khỏi tệp cấu hình
				sed -i "/^# BEGIN_PEER $client$/,/^# END_PEER $client$/d" /etc/wireguard/wg0.conf
				echo
				echo "$client removed!"
			else
				echo
				echo "$client removal aborted!"
			fi
			exit
		;;
		3)
			echo
			read -p "Xác nhận loại bỏ WireGuard? [y/N]: " remove
			until [[ "$remove" =~ ^[yYnN]*$ ]]; do
				echo "$remove: invalid selection."
				read -p "Xác nhận loại bỏ WireGuard? [y/N]: " remove
			done
			if [[ "$remove" =~ ^[yY]$ ]]; then
				port=$(grep '^ListenPort' /etc/wireguard/wg0.conf | cut -d " " -f 3)
				if systemctl is-active --quiet firewalld.service; then
					ip=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s 10.7.0.0/24 '"'"'!'"'"' -d 10.7.0.0/24' | grep -oE '[^ ]+$')
					# Sử dụng cả quy tắc vĩnh viễn và không vĩnh viễn để tránh tải lại tường lửa.
					firewall-cmd --remove-port="$port"/udp
					firewall-cmd --zone=trusted --remove-source=10.7.0.0/24
					firewall-cmd --permanent --remove-port="$port"/udp
					firewall-cmd --permanent --zone=trusted --remove-source=10.7.0.0/24
					firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j SNAT --to "$ip"
					firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j SNAT --to "$ip"
					if grep -qs 'fddd:2c4:2c4:2c4::1/64' /etc/wireguard/wg0.conf; then
						ip6=$(firewall-cmd --direct --get-rules ipv6 nat POSTROUTING | grep '\-s fddd:2c4:2c4:2c4::/64 '"'"'!'"'"' -d fddd:2c4:2c4:2c4::/64' | grep -oE '[^ ]+$')
						firewall-cmd --zone=trusted --remove-source=fddd:2c4:2c4:2c4::/64
						firewall-cmd --permanent --zone=trusted --remove-source=fddd:2c4:2c4:2c4::/64
						firewall-cmd --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j SNAT --to "$ip6"
						firewall-cmd --permanent --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j SNAT --to "$ip6"
					fi
				else
					systemctl disable --now wg-iptables.service
					rm -f /etc/systemd/system/wg-iptables.service
				fi
				systemctl disable --now wg-quick@wg0.service
				rm -f /etc/systemd/system/wg-quick@wg0.service.d/boringtun.conf
				rm -f /etc/sysctl.d/99-wireguard-forward.conf
				# Các gói khác nhau đã được cài đặt nếu hệ thống được container hóa hay không
				if [[ ! "$is_container" -eq 0 ]]; then
					if [[ "$os" == "ubuntu" ]]; then
						# Ubuntu
						rm -rf /etc/wireguard/
						apt-get remove --purge -y wireguard wireguard-tools
					elif [[ "$os" == "debian" && "$os_version" -ge 11 ]]; then
						# Debian 11 or higher
						rm -rf /etc/wireguard/
						apt-get remove --purge -y wireguard wireguard-tools
					elif [[ "$os" == "debian" && "$os_version" -eq 10 ]]; then
						# Debian 10
						rm -rf /etc/wireguard/
						apt-get remove --purge -y wireguard wireguard-dkms wireguard-tools
					elif [[ "$os" == "centos" && "$os_version" -eq 8 ]]; then
						# CentOS 8
						dnf remove -y kmod-wireguard wireguard-tools
						rm -rf /etc/wireguard/
					elif [[ "$os" == "centos" && "$os_version" -eq 7 ]]; then
						# CentOS 7
						yum remove -y kmod-wireguard wireguard-tools
						rm -rf /etc/wireguard/
					elif [[ "$os" == "fedora" ]]; then
						# Fedora
						dnf remove -y wireguard-tools
						rm -rf /etc/wireguard/
					fi
				else
					{ crontab -l 2>/dev/null | grep -v '/usr/local/sbin/boringtun-upgrade' ; } | crontab -
					if [[ "$os" == "ubuntu" ]]; then
						# Ubuntu
						rm -rf /etc/wireguard/
						apt-get remove --purge -y wireguard-tools
					elif [[ "$os" == "debian" && "$os_version" -ge 11 ]]; then
						# Debian 11 or higher
						rm -rf /etc/wireguard/
						apt-get remove --purge -y wireguard-tools
					elif [[ "$os" == "debian" && "$os_version" -eq 10 ]]; then
						# Debian 10
						rm -rf /etc/wireguard/
						apt-get remove --purge -y wireguard-tools
					elif [[ "$os" == "centos" && "$os_version" -eq 8 ]]; then
						# CentOS 8
						dnf remove -y wireguard-tools
						rm -rf /etc/wireguard/
					elif [[ "$os" == "centos" && "$os_version" -eq 7 ]]; then
						# CentOS 7
						yum remove -y wireguard-tools
						rm -rf /etc/wireguard/
					elif [[ "$os" == "fedora" ]]; then
						# Fedora
						dnf remove -y wireguard-tools
						rm -rf /etc/wireguard/
					fi
					rm -f /usr/local/sbin/boringtun /usr/local/sbin/boringtun-upgrade
				fi
				echo
				echo "WireGuard đã hủy bỏ!"
			else
				echo
				echo "Loại bỏ WireGuard bị hủy bỏ!"
			fi
			exit
		;;
		4)
			exit
		;;
	esac
fi