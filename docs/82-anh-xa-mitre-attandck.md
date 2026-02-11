---
title: 'End-to-End Incident Response Simulation: From Detection to Recovery'
label: 'CHƯƠNG 8.2: ÁNH XẠ MITRE ATT&CK'
slug: 82-anh-xa-mitre-attandck
description: >-
  Dự án mô phỏng quy trình SOC khép kín: Từ Monitor, Detection đến Digital
  forensics và Recovery kết hợp Mini-SOAR Engine bằng Python theo kiến trúc bảo
  mật 6 lớp giúp tự động hóa toàn bộ quy trình.
visibility: PUBLIC
---
# CHƯƠNG 8.2 : ÁNH XẠ MITRE ATT\&CK

Phân tích TTPs với MITRE ATT\&CK Framework

**Nội dung:**

Để chuẩn hóa các hành vi tấn công , tôi đã tạo ra bảng MITRE ATT\&CK phù hợp

| **Tactic**            | **ID**    | **Technique**             | **Bằng chứng thực tế trong Lab**                       |
| --------------------- | --------- | ------------------------- | ------------------------------------------------------ |
| **Initial Access**    | T1566.002 | Phishing                  | Email lừa đảo dẫn dụ người dùng click link.            |
| **Credential Access** | T1110.001 | Password Guessing         | Sử dụng **Hydra** brute-force mật khẩu user thanh.     |
| **Execution**         | T1059.001 | PowerShell                | **Evil-WinRM** gọi powershell .exe để chạy lệnh từ xa. |
| **Discovery**         | T1087     | Account Discovery         | Lệnh whoami (phát hiện trong Sysmon Event 1).          |
| **Lateral Movement**  | T1021.006 | Windows Remote Management | Điều khiển máy qua Port 5985.                          |
| **Collection**        | T1005     | Data from Local System    | Lệnh cat đọc file text.                                |
| **Impact**            | T1486     | Data Encrypted for Impact | Script PowerShell thực hiện mã hóa file.               |
| **Defense Evasion**   | T1070.004 | File Deletion             | Tự xóa script độc hại sau khi chạy xong.               |
