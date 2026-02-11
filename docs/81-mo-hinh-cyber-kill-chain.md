---
title: 'End-to-End Incident Response Simulation: From Detection to Recovery'
label: 'CHƯƠNG 8.1: MÔ HÌNH CYBER KILL CHAIN'
slug: 81-mo-hinh-cyber-kill-chain
description: >-
  Dự án mô phỏng quy trình SOC khép kín: Từ Monitor, Detection đến Digital
  forensics và Recovery kết hợp Mini-SOAR Engine bằng Python theo kiến trúc bảo
  mật 6 lớp giúp tự động hóa toàn bộ quy trình.
visibility: PUBLIC
---
# CHƯƠNG 8.1 : MÔ HÌNH CYBER KILL CHAIN

**Nội dung:** Mình sử dụng mô hình Cyber Kill Chain để tái hiện lại "câu chuyện" của cuộc tấn công theo trình tự thời gian, từ lúc kẻ tấn công (Attacker) bắt đầu thăm dò cho đến khi dữ liệu bị mã hóa.

1. **Reconnaissance :**

   * Attacker dựng MailHog và gửi Email phishing.

   * Nạn nhân truy cập vào link giả mạo host trên Python HTTP Server, để lộ địa chỉ IP.

   * Attacker dùng Nmap quét và phát hiện cổng 5985 dịch vụ WinRM đang mở.

2. **Weaponization :**

   * Attacker chuẩn bị công cụ Hydra và Evil-WinRM .

   * Tạo sẵn script mã độc [encrypt.ps1](https://github.com/BuiNhatThanh2091/LAB0-END-TO-END-INCIDENT-RESPONSE-SIMULATION/blob/main/scripts/attacker_sim/encrypt.ps1) có khả năng mã hóa file.

3. **Delivery:**

   * Script mã độc không gửi trực tiếp qua mail mà được Attacker "upload" thẳng vào máy nạn nhân sau khi đã chiếm được quyền điều khiển thông qua giao thức WinRM.

4. **Exploitation:**

   * Sử dụng Hydra tấn công Brute-force vào cổng 5985 và đoán đúng mật khẩu yếu của user thanh.

5. **Installation:**

   * Thiết lập một phiên Remote Shell ổn định bằng Evil-WinRM.

6. **Command and Control :**

   * Máy Attacker - Kali gửi các lệnh điều khiển (ls, whoami, upload, download , cat, cd , exit) tới máy nạn nhân và nhận kết quả trả về qua giao thức HTTP/SOAP của WinRM.

7. **Actions on Objectives :**

   * Đọc trộm dữ liệu nhạy cảm .

   * Thực thi script [encrypt.ps1](https://github.com/BuiNhatThanh2091/LAB0-END-TO-END-INCIDENT-RESPONSE-SIMULATION/blob/main/scripts/attacker_sim/encrypt.ps1) để mã hóa file tống tiền.
