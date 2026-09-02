# WAF-Shield Enterprise v3.1 — Packet Firewall Anti-DDoS cho Windows

**WAF-Shield Enterprise** là giải pháp tường lửa và trung tâm điều hành bảo mật (SOC) chuyên dụng chống tấn công từ chối dịch vụ (**Anti-DDoS**) hoạt động trực tiếp trên nhân mạng Windows (Windows Server 2012, 2012 R2, 2016, 2019, 2022, 2025 và Windows 10, Windows 11).

Hệ thống chặn gói IPv4 qua WinDivert trước khi lưu lượng tới socket ứng dụng. Đây là lớp giảm thiểu tại host; không thể thay thế scrubbing upstream nếu đường truyền đã bị bão hòa.

🌐 **Trang Chủ Triển Lãm & Hướng Dẫn Online (GitHub Pages)**: `trangchu/index.html`


---

## TÍNH NĂNG NỔI BẬT TRÊN PHIÊN BẢN v3.1

1. ** Giám Sát Lưu Lượng Mạng 2 Chiều Toàn Diện (Bidirectional RX & TX Telemetry)**:
   - Theo dõi song song **Lưu lượng đi vào (Inbound RX)** và **Lưu lượng phản hồi đi ra (Outbound TX)**.
   - Thống kê chi tiết cả số gói tin/giây (**PPS**) và băng thông/giây (**Bps / Mbps / Gbps**).
   - Biểu đồ nhịp sóng 60 giây thời gian thực 3 dải: **Lưu lượng sạch vào (Xanh lá)**, **Lưu lượng phản hồi ra (Xanh Cyan)**, và **Lưu lượng DDoS bị triệt tiêu (Đỏ)**.

2. **🎛️ 4 Chế Độ Phòng Thủ 1 Chạm (Instant Defense Presets)**:
   - ** Full-Stack Hybrid Shield**: Chế độ tối ưu hoàn hảo cho máy chủ chạy **cả Game Server (UDP) và Website / REST API (TCP)** cùng lúc.
   - ** Universal Game Server Shield**: Tối ưu chuyên sâu cho Game Server thời gian thực (**UDP Realtime**), bật bộ lọc Query Spam DPI và điều phối 120 PPS/luồng.
   - **High-Concurrency Web & API Shield**: Theo dõi trạng thái SYN/ACK, giới hạn theo IP/subnet và dọn kết nối treo cho Web Server, REST API và WebSocket.
   - ** Maximum Lockdown Defense**: Khóa chặt máy chủ 24/7 chỉ cho phép IP Việt Nam và bật toàn bộ lớp bảo vệ nghiêm ngặt.

3. **🌍 Bộ Lọc Vị Trí Địa Lý Geo-IP Việt Nam**:
   - Tích hợp sẵn cơ sở dữ liệu `vn.zone` chứa hàng chục nghìn dải IP Việt Nam (Viettel, VNPT, FPT, CMC...).
   - Chế độ **ONLY VN**: Khóa 100% toàn bộ dải IP quốc tế chỉ với 1 click.
   - Chế độ **AUTO**: Tự động cho phép IP quốc tế khi thời bình (Peace Mode) và tự động khóa IP quốc tế khi bị bão tấn công (War Mode).

4. **🛡️ Bộ Icon 3D Cyber Shield Siêu Đẹp (Masterpiece AAA Quality)**:
   - Nhúng trực tiếp vào Win32 PE Resource của file `.exe`. Hiển thị icon 3D phát sáng sắc nét trong **Task Manager**, **Taskbar**, **Windows Explorer** và **Web SOC Dashboard**.

5. **⚡ Tự Động Nhận Diện Kết Nối (Zero-Drop TCP Adoption)**:
   - Mọi kết nối Remote Desktop (3389), Web (80, 443) hoặc Game khi gửi dữ liệu ứng dụng thực tế sẽ được đưa ngay vào danh sách tin cậy, đảm bảo không bao giờ bị rớt kết nối quản trị VPS.



---

## 🏗️ KIẾN TRÚC MA TRẬN PHÒNG THỦ 5 LỚP

```text
               ┌────────────────────────────────────────────────────────┐
               │    LƯU LƯỢNG MẠNG TỪ INTERNET (INBOUND RX TRAFFIC)      │
               └──────────────────────────┬─────────────────────────────┘
                                          │
    [Lớp 0: IP Filter]                    ▼
    ├── Danh Sách Trắng (Whitelist) ──────────────► [CHO QUA 100%]
    └── Danh Sách Đen (Blacklist / Geo-IP) ───────► [HỦY TẠI CHỖ (DROP)]
                                          │
    [Lớp 1: RFC Scrubbing]                ▼
    └── Kiểm tra Header, Hủy gói dị dạng, Lọc phản xạ UDP (DNS 53, NTP 123...)
                                          │
    [Lớp 2: Socket Discovery]             ▼
    └── Tự động phát hiện cổng mở (1-65535), Hủy ngay gói tin gửi tới cổng đóng
                                          │
                                ┌─────────┴─────────┐
                                │                   │
                    [Lớp 3: TCP Shield]     [Lớp 4: UDP Shield]
                    ├── Stateless SYN Cookie ├── Token Bucket (Per-Flow/IP)
                    ├── Anti-Slowloris       ├── Anti-Carpet Bombing (/24)
                    └── Kết nối đồng thời     └── Game Query DPI & Entropy
                                │                   │
                                └─────────┬─────────┘
                                          ▼
               ┌────────────────────────────────────────────────────────┐
               │             MÁY CHỦ ỨNG DỤNG / GAME SERVER              │
               └────────────────────────────────────────────────────────┘
```

---

## 🚀 HƯỚNG DẪN CÀI ĐẶT & VẬN HÀNH

Thư mục phát hành `WAF-Shield-Deploy/` đã tích hợp sẵn các file thực thi tiện lợi:

### Cách 1: Chạy Trực Tiếp Bằng Giao Diện Console & Web
* Nhấp đúp chuột vào file **`CHAY_WAF.bat`** (hoặc mở Command Prompt với quyền *Run as Administrator* và gõ `waf-game.exe`).
* Bảng điều khiển Console sẽ hiển thị đầy đủ thông số PPS, Bps, trạng thái phòng thủ.
* Mở trình duyệt truy cập: **`http://localhost:8080`** (hoặc `http://IP_VPS:8080`).

### Cách 2: Cài Đặt Chạy Ngầm 24/7 (Windows Service)
Để WAF tự động chạy ngầm bảo vệ máy chủ ngay khi VPS bật nguồn mà không cần đăng nhập Remote Desktop:
* **Bước 1**: Nhấp chuột phải vào file **`CAI_DAT_SERVICE.bat`** $\to$ Chọn **Run as Administrator**.
* **Bước 2**: Nhấp chuột phải vào file **`BAT_SERVICE.bat`** $\to$ Chọn **Run as Administrator** để khởi chạy dịch vụ.
* **Tắt dịch vụ khi cần**: Chạy file **`TAT_SERVICE.bat`**.
* **Gỡ bỏ hoàn toàn dịch vụ**: Chạy file **`GO_BO_SERVICE.bat`**.

---

## 🖥️ GIAO DIỆN WEB SOC DASHBOARD TRỰC TUYẾN (Cổng 8080)

| Tab Chức Năng | Mô Tả Chi Tiết |
| :--- | :--- |
| **Overview & Traffic** | Biểu đồ sóng thời gian thực 60 giây (RX Clean, TX Outbound, Blocked DDoS), thẻ KPI lưu lượng mạng 2 chiều, phân loại đòn tấn công. |
| **Attack Radar** | Thống kê số lượng gói tin bị chặn bởi từng lớp: Subnet /24, UDP Amplification, Query DPI, Out-of-State. |
| **Presets & Tuning** | Kích hoạt 1 chạm 3 chế độ: Universal Game Shield,  Web & API Shield, Strict Lockdown. |
| **Access Control** | Quản lý danh sách cấm (Blacklist) và danh sách tin cậy (Whitelist), hỗ trợ thêm/xóa nhanh IP. |
| **Port Inspector** | Danh sách toàn bộ các cổng TCP/UDP đang mở trên máy chủ và lớp khiên bảo vệ tương ứng. |
| **Security Logs** | Luồng nhật ký sự kiện bảo mật trực tiếp theo thời gian thực (Live Event Stream). |

---

## ⚙️ CẤU HÌNH TÙY CHỈNH NÂNG CAO (`config.json`)

Mọi thông số đều có thể điều chỉnh linh hoạt trong file `config.json`:

```json
{
  "system_mode": "AUTO",
  "peace_mode": {
    "udp_pps_per_flow": 120,
    "udp_bps_per_flow": 1048576,
    "udp_pps_per_ip": 350,
    "subnet_pps_limit": 1200,
    "tcp_max_conn_per_ip": 60,
    "tcp_conn_rate_per_ip": 25,
    "tcp_idle_timeout_sec": 90
  },
  "war_mode": {
    "trigger_pps": 4000,
    "trigger_bps": 31457280,
    "udp_pps_per_flow": 35,
    "udp_pps_per_ip": 80,
    "subnet_pps_limit": 200,
    "geoip_mode": "AUTO"
  },
  "web_dashboard": {
    "enabled": true,
    "port": 8080,
    "username": "admin",
    "password": "change_me_here",
    "allow_lan": false
  }
}
```

---

## 📦 THÀNH PHẦN FILE GÓI TRIỂN KHAI

* **`waf-game.exe`**: File thực thi chính của WAF (Tích hợp sẵn Web Server SOC, NDIS Engine, Tường lửa Anti-DDoS).
* **`WinDivert.dll` & `WinDivert64.sys`**: Thành phần bắt và tái chèn gói trên Windows.

> Production: giữ dashboard ở localhost. Nếu bật `allow_lan`, phải đặt cả `username` và mật khẩu mạnh; WAF sẽ từ chối mở dashboard LAN khi thiếu xác thực.
* **`config.json`**: File cấu hình thông số phòng thủ WAF.
* **`resources/geo/vn.zone`**: Cơ sở dữ liệu IP Việt Nam.
* **Các file `.bat` điều khiển**: `CHAY_WAF.bat`, `CAI_DAT_SERVICE.bat`, `BAT_SERVICE.bat`, `TAT_SERVICE.bat`, `GO_BO_SERVICE.bat`.


---
*© 2026 WAF-Shield Enterprise Cyber Security — All Rights Reserved.*
