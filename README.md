# Cài đặt WireGuard VPN Server
Hướng Dẫn cài WireGuard VPN
- Đầu tiên, bạn cần phải có sẵn 1 VPS với quyền truy cập root. Bạn có thể đăng ký 1 VPS mới Hetzner, UpCloud hay DigitalOcean tuỳ thích. Hoặc sử dụng bất kỳ VPS nào bạn đang có sẵn.
- Tiếp theo SSH vào VPS với tài khoản root và cài đặt Wireguard VPN với lệnh sau.
```
wget raw.githubusercontent.com/AikoCute/WireGuard-VPN/aiko/wireguard-Aiko-Install.sh -O wireguard-install.sh && bash wireguard-install.sh
```
Nếu VPS / Server của bạn có nhiều IP mạng, nhớ chọn IP Public của VPS.
```
Which IPv4 address should be used?
     1) 5.196.89.40
     2) 172.17.0.1
IPv4 address [1]: 1
```
- Tiếp theo nhập thông tin theo yêu cầu của script cài đặt.
```
## Chọn port, bấm Enter để giữ nguyên port mặc định 51820
What port should WireGuard listen to? 
Port [51820]:

## Chọn tên
Enter a name for the first client:
Name [client]: aiko

## Chọn DNS Server
Select a DNS server for the client:
   1) Current system resolvers
   2) Google
   3) 1.1.1.1
   4) OpenDNS
   5) Quad9
   6) AdGuard
DNS server [1]: 2

WireGuard installation is ready to begin.
Press any key to continue...
## Bấm nút bất kỳ để tiếp tục
```
- Đơi khoảng vài phút cho script cài đặt và cấu hình Wireguard VPN tự động cho bạn. Sau khi hoàn tất, bạn sẽ nhận được thông báo như sau.

    1 : QR code 
    2 : Cấu hình máy khách có sẵn trong: /root/aiko.conf
    Có thể thêm khách hàng mới bằng cách chạy lại tập lệnh này.

## Tạo thêm tài khoản client
- Bạn có thể chạy lại lệnh cài đặt thêm lần nữa để tạo thêm nhiều tài khoản mới.
```
wget raw.githubusercontent.com/AikoCute/WireGuard-VPN/aiko/wireguard-Aiko-Install.sh -O wireguard-install.sh && bash wireguard-install.sh
```
- Hệ thống sẽ tự động nhận ra WireGuard đã được cài đặt và hiện thông báo như dưới đây. Chọn 1 để tạo thêm client mới, 2 để xoá client hiện có, 3 để xoá WireGuard và 4 để thoát ra
```
WireGuard is already installed.

Select an option:
   1) Add a new client
   2) Remove an existing client
   3) Remove WireGuard
   4) Exit
Option: 
```
Để xem lại QR Code của tài khoản đã tạo bạn dùng lệnh sau
```
qrencode -t UTF8 < aiko.conf
```
Nhớ thay thế `aiko.conf` bằng tên file tương ứng với tài khoản bạn đã tạo trước đó. File này được lưu ở thư mục `/root`

# Cài đặt WireGuard Client
 - update sau