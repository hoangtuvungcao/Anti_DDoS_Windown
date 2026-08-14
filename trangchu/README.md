# 🌐 Hướng Dẫn Bật GitHub Pages Cho Trang Chủ Triển Lãm

Thư mục `trangchu/` chứa toàn bộ mã nguồn tĩnh (**HTML5, Vanilla CSS, Pure JavaScript**) của trang chủ triển lãm WAF-Shield Enterprise.

---

## 🚀 CÁCH 1: BẬT GITHUB PAGES TỰ ĐỘNG TRÊN REPOSITORY

1. Đẩy mã nguồn lên GitHub:
   ```bash
   git add .
   git commit -m "Add official exhibition landing page for GitHub Pages"
   git push origin main
   ```
2. Mở trình duyệt vào repository: **`https://github.com/hoangtuvungcao/Anti_DDoS_Windown`**
3. Vào **Settings** $\to$ **Pages** (ở cột bên trái).
4. Tại mục **Build and deployment**:
   * **Source**: Chọn `Deploy from a branch`.
   * **Branch**: Chọn `main` và thư mục `/trangchu` (hoặc chuyển nội dung `trangchu/` ra `docs/` nếu muốn chọn `/docs`).
5. Bấm **Save**. Trang chủ của bạn sẽ hoạt động trực tiếp tại:
   **`https://hoangtuvungcao.github.io/Anti_DDoS_Windown/`**

---

## 💻 CÁCH 2: XEM TRỰC TIẾP TRÊN MÁY LOCAL
* Chỉ cần nhấp đúp chuột vào file **`index.html`** để mở ngay trên bất kỳ trình duyệt nào (Chrome, Edge, Firefox).
* Hoặc chạy với Python HTTP Server:
  ```bash
  cd trangchu
  python3 -m http.server 3000
  ```
  Truy cập: `http://localhost:3000`
