---
title: 'End-to-End Incident Response Simulation: From Detection to Recovery'
label: 'CHƯƠNG 8.4: CHỈ SỐ IOCs & ARTIFACTS'
slug: 84-chi-so-iocs-and-artifacts
description: >-
  Dự án mô phỏng quy trình SOC khép kín: Từ Monitor, Detection đến Digital
  forensics và Recovery kết hợp Mini-SOAR Engine bằng Python theo kiến trúc bảo
  mật 6 lớp giúp tự động hóa toàn bộ quy trình.
visibility: PUBLIC
---
# CHƯƠNG 8.4 : CHỈ SỐ IOCs & ARTIFACTS

**Tổng hợp Indicators of Compromise**

Đây là phần ta thu thập được sau quá trình Digital Forensics bằng sử dụng FTK Imager dump RAM/Disk sau khi đã cô lập máy. Các chỉ số này có thể dùng để cấu hình Firewall hoặc Rules trên EDR.

**1. Network Indicators**

| **Loại**         | **Giá trị**                                            | **Mô tả**                             |
| ---------------- | ------------------------------------------------------ | ------------------------------------- |
| **Attacker IP**  | 10.10.10.130                                           | IP thực hiện Scan, Brute-force và C2. |
| **Phishing URL** | [http://10.10.10.130:8080/](http://10.10.10.130:8080/) | Link độc hại gửi qua Email.           |
| **Target Port**  | 5985                                                   | Cổng WinRM bị khai thác.              |

**2. Host-based Indicators**

| **Loại**              | **Giá trị**                                                                                                                                | **Nguồn phát hiện**                                                                     |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------- |
| **Malicious Process** | Parent: wsmprovhost.exe                                                                                                                    | **Event 4104** & **Sysmon** (Event 1). Đây là hành vi đặc trưng của WinRM Remote Shell. |
| **File Name**         | encrypt.ps1                                                                                                                                | encrypt.ps1 Script thực thi mã hóa.                                                     |
| **Access Artifact**   | Event ID 4663                                                                                                                              | **Security.evtx**. Chứng minh dữ liệu đã bị đọc trộm.                                   |
| **Encrypted Ext**     | .aes                                                                                                                                       | File dữ liệu bị đổi đuôi sau khi mã hóa.                                                |
| **Script Content**    | [encrypt.ps1](https://github.com/BuiNhatThanh2091/LAB0-END-TO-END-INCIDENT-RESPONSE-SIMULATION/blob/main/scripts/attacker_sim/encrypt.ps1) | **Sysmon Event 4104**. Nội dung script được log lại rõ ràng.                            |
