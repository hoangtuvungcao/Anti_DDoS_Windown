# WAF-Game - Tường lửa Anti-DDoS cho Windows

WAF-Game là công cụ tường lửa/anti-DDoS chạy trực tiếp trên Windows, sử dụng WinDivert để bắt, phân tích và lọc gói tin TCP/UDP theo thời gian thực. Dự án hướng tới việc bảo vệ server game hoặc các dịch vụ mạng chạy trên Windows bằng cơ chế tự động phát hiện cổng, giám sát lưu lượng, giới hạn tốc độ, blacklist IP và dashboard CLI.

Ứng dụng cần chạy bằng quyền Administrator vì WinDivert phải nạp driver ở tầng mạng của hệ điều hành.

## Demo


![WAF-Game Demo](https://github.com/hoangtuvungcao/Anti_DDoS_Windown/blob/main/resources/win.jpg)



## Tính năng chính

- Bảo vệ dịch vụ TCP và UDP bằng WinDivert.
- Tự động quét và phát hiện các cổng đang mở trên hệ thống.
- Dashboard CLI hiển thị lưu lượng, số gói bị chặn, flow đang hoạt động, cổng được bảo vệ và blacklist.
- Hỗ trợ 3 chế độ vận hành: `AUTO`, `ON`, `OFF`.
- Tự động chuyển giữa Peace Mode và War Mode dựa trên ngưỡng PPS/BPS.
- Giới hạn UDP theo từng flow và theo từng IP nguồn.
- Giới hạn số kết nối TCP trên mỗi IP.
- Tự dọn kết nối TCP nhàn rỗi theo thời gian timeout.
- Blacklist IP/flow có thời gian hết hạn.
- Hỗ trợ kiểm tra entropy payload UDP để giảm traffic bất thường.
- Hỗ trợ Geo-IP mode cho chính sách VN-only khi cần.
- Lưu log vận hành vào file cấu hình sẵn.
- Có thể thay đổi một số rule trực tiếp trong dashboard mà không cần tắt chương trình.

## Cách hoạt động tổng quan

1. Chương trình kiểm tra quyền Administrator.
2. Kiểm tra sự tồn tại của `WinDivert.dll` và `WinDivert64.sys`.
3. Đọc cấu hình từ `config.json`.
4. Khởi tạo engine lọc gói tin, metrics và logger.
5. Tự động quét các cổng TCP/UDP đang hoạt động.
6. Hiển thị dashboard CLI.
7. Theo dõi lưu lượng và tự chuyển trạng thái nếu phát hiện traffic vượt ngưỡng.
8. Khi thoát, chương trình dừng engine và gỡ driver WinDivert một cách an toàn.

## Yêu cầu hệ thống

- Windows 64-bit.
- Terminal chạy bằng quyền Administrator.
- Go theo phiên bản trong `go.mod` nếu muốn build từ source.
- Bộ file WinDivert đặt đúng đường dẫn:
  - `resources/bin/WinDivert.dll`
  - `resources/bin/WinDivert64.sys`
- File cấu hình:
  - `config.json`

## Cấu trúc thư mục

```text
.
├── main.go                     # Điểm khởi động chương trình
├── config.json                 # File cấu hình chính
├── go.mod                      # Khai báo module Go
├── waf-game.exe                # File chạy đã build sẵn nếu có
├── pkg/
│   ├── cli/                    # Dashboard CLI và phím điều khiển
│   ├── config/                 # Đọc/ghi cấu hình JSON
│   ├── datastore/              # Cấu trúc dữ liệu cache, token bucket
│   ├── engine/                 # Engine lọc gói, TCP/UDP shield, mode manager
│   ├── packet/                 # Parser gói tin
│   ├── stats/                  # Metrics, thống kê lưu lượng
│   └── windivert/              # Binding gọi WinDivert
├── resources/
│   ├── bin/                    # DLL/SYS của WinDivert
│   ├── geo/                    # Dữ liệu Geo-IP nội bộ
│   └── logs/                   # Log vận hành
└── winres/                     # Icon và tài nguyên build Windows
```

## Chạy bản có sẵn

Mở PowerShell hoặc Command Prompt bằng quyền Administrator, sau đó chạy:

```powershell
.\waf-game.exe
```

Nếu chương trình báo thiếu WinDivert, hãy kiểm tra lại các file:

```text
resources/bin/WinDivert.dll
resources/bin/WinDivert64.sys
```

## Chạy từ source

```powershell
go run .
```

Lưu ý: lệnh này vẫn cần chạy trong terminal có quyền Administrator.

## Build file EXE

```powershell
go build -o waf-game.exe .
```

Sau khi build, khi copy sang máy khác cần mang theo tối thiểu:

```text
waf-game.exe
config.json
resources/bin/WinDivert.dll
resources/bin/WinDivert64.sys
resources/geo/vn.zone
```

Nếu muốn giữ log đúng vị trí mặc định, giữ thêm thư mục:

```text
resources/logs/
```

## Cấu hình

File cấu hình chính là `config.json`. Khi chương trình chạy, một số thay đổi từ dashboard có thể được ghi ngược lại vào file này.

### Cấu hình chung

| Trường | Ý nghĩa |
| --- | --- |
| `workers` | Số worker xử lý gói tin. Tăng giá trị này nếu máy có nhiều CPU core và lưu lượng cao. |
| `log_file` | Đường dẫn file log. Mặc định là `resources/logs/shield.log`. |
| `system_mode` | Chế độ hệ thống: `AUTO`, `ON`, `OFF`. |

### `system_mode`

| Giá trị | Ý nghĩa |
| --- | --- |
| `AUTO` | Tự động chuyển Peace/War theo traffic thực tế. Đây là chế độ khuyến nghị. |
| `ON` | Ép hệ thống ở trạng thái bảo vệ mạnh. |
| `OFF` | Tắt phần bảo vệ chủ động, dùng khi cần kiểm tra hoặc debug. |

### `peace_mode`

Đây là cấu hình khi lưu lượng bình thường.

| Trường | Ý nghĩa |
| --- | --- |
| `udp_pps_per_flow` | Số packet UDP tối đa mỗi giây cho một flow. |
| `udp_bps_per_flow` | Số byte UDP tối đa mỗi giây cho một flow. |
| `udp_pps_per_ip` | Số packet UDP tối đa mỗi giây cho một IP nguồn. |
| `blacklist_duration_sec` | Thời gian blacklist tính bằng giây. |
| `tcp_max_conn_per_ip` | Số kết nối TCP tối đa trên mỗi IP. |
| `tcp_idle_timeout_sec` | Thời gian timeout cho kết nối TCP nhàn rỗi. |

### `war_mode`

Đây là cấu hình khi hệ thống phát hiện lưu lượng tấn công hoặc khi ép chế độ bảo vệ mạnh.

| Trường | Ý nghĩa |
| --- | --- |
| `trigger_pps` | Ngưỡng packet/giây để kích hoạt War Mode. |
| `trigger_bps` | Ngưỡng byte/giây để kích hoạt War Mode. |
| `cooldown_sec` | Thời gian chờ trước khi rời War Mode sau khi traffic ổn định. |
| `udp_pps_per_flow` | Giới hạn UDP mỗi flow khi ở War Mode. |
| `enable_dpi` | Bật/tắt kiểm tra sâu payload nếu engine dùng rule này. |
| `entropy_mode` | Chế độ kiểm tra entropy: `AUTO`, `ON`, `OFF`. |
| `enable_twoway` | Bật/tắt xác minh hai chiều cho UDP nếu engine dùng rule này. |
| `geoip_mode` | Chế độ Geo-IP: `AUTO`, `ON`, `OFF`. |
| `strict_whitelist` | Ưu tiên whitelist khi áp dụng luật nghiêm ngặt. |

### `cache`

| Trường | Ý nghĩa |
| --- | --- |
| `max_entries` | Số entry tối đa trong cache. |
| `ttl_sec` | Thời gian sống của entry cache. |
| `sweep_interval_sec` | Chu kỳ dọn cache. |
| `shards` | Số shard để giảm lock contention khi xử lý nhiều traffic. |

### `discovery`

| Trường | Ý nghĩa |
| --- | --- |
| `interval_sec` | Chu kỳ quét port đang mở. |
| `exclude_ports` | Danh sách port không muốn tự động bảo vệ. |

Ví dụ loại trừ port `80` và `443`:

```json
"discovery": {
  "interval_sec": 5,
  "exclude_ports": [80, 443]
}
```

### Danh sách IP

| Trường | Ý nghĩa |
| --- | --- |
| `whitelist_ips` | IP được cho phép/ưu tiên bỏ qua khi lọc. |
| `blacklist_ips` | IP bị chặn sẵn từ lúc khởi động. |

Ví dụ:

```json
"whitelist_ips": ["127.0.0.1", "192.168.1.10"],
"blacklist_ips": ["203.0.113.10"]
```

## Dashboard CLI

Dashboard hiển thị các thông tin chính:

- Trạng thái engine đang hoạt động.
- Chế độ hiện tại: `AUTO-PEACE`, `AUTO-WAR`, `ON-WAR`, `OFF-PEACE`.
- Uptime của chương trình.
- Lưu lượng inbound theo PPS/BPS.
- Lưu lượng bị drop theo PPS/BPS.
- Cổng TCP/UDP đang được bảo vệ.
- Số UDP flow đang hoạt động.
- Số TCP connection đã xác minh.
- Thống kê drop theo từng lớp kiểm tra.
- Danh sách blacklist đang có hiệu lực.
- Các cấu hình có thể chỉnh nhanh.

## Phím tắt

| Phím | Chức năng |
| --- | --- |
| `M` | Về màn hình chính. |
| `B` | Xem danh sách blacklist. |
| `S` | Mở trang cấu hình nhanh. |
| `W` | Đổi chế độ theo vòng `AUTO -> ON -> OFF -> AUTO`. |
| `A` | Chuyển nhanh về `AUTO`. |
| `1` | Đổi giới hạn TCP connections/IP trong trang Settings. |
| `2` | Đổi TCP idle timeout trong trang Settings. |
| `3` | Đổi UDP flow PPS limit trong trang Settings. |
| `4` | Đổi UDP IP PPS limit trong trang Settings. |
| `5` | Đổi UDP entropy mode trong trang Settings. |
| `6` | Đổi Geo-IP mode trong trang Settings. |
| `Q` | Thoát chương trình an toàn. |

## Log và xử lý lỗi

Log mặc định nằm tại:

```text
resources/logs/shield.log
```

Một số lỗi thường gặp:

| Lỗi | Cách kiểm tra |
| --- | --- |
| Chương trình yêu cầu Administrator | Đóng terminal, mở lại bằng `Run as Administrator`. |
| Thiếu WinDivert | Kiểm tra `resources/bin/WinDivert.dll` và `resources/bin/WinDivert64.sys`. |
| Không đọc được cấu hình | Kiểm tra JSON trong `config.json` có hợp lệ không. |
| Không ghi được log | Kiểm tra thư mục `resources/logs/` có tồn tại và có quyền ghi không. |
| Không thấy port được bảo vệ | Kiểm tra dịch vụ game/server đã mở port chưa và `exclude_ports` có loại trừ port đó không. |

## Khuyến nghị triển khai

- Nên chạy thử trên môi trường staging trước khi dùng cho server thật.
- Giữ `system_mode` là `AUTO` nếu chưa có lý do cụ thể để ép `ON` hoặc `OFF`.
- Không đặt ngưỡng quá thấp nếu server có lượng người chơi thật lớn, vì có thể chặn nhầm traffic hợp lệ.
- Theo dõi `shield.log` trong giai đoạn đầu để tinh chỉnh `peace_mode` và `war_mode`.
- Với server nhiều traffic UDP, nên tăng `workers` phù hợp với số CPU core.
- Khi cập nhật file EXE, giữ nguyên `config.json` nếu không muốn mất cấu hình cũ.

## Kiểm thử

Chạy test:

```powershell
go test ./...
```

Một số test có thể phụ thuộc vào môi trường Windows/WinDivert. Nếu test hoặc runtime liên quan tới driver thất bại trên máy không phải Windows, hãy kiểm tra lại môi trường chạy.

## License

Dự án hiện chưa có license.
