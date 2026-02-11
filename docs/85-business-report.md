---
title: 'End-to-End Incident Response Simulation: From Detection to Recovery'
label: 'CHƯƠNG 8.5: INCIDENT RESPONSE REPORT'
slug: 85-business-report
description: >-
  Dự án mô phỏng quy trình SOC khép kín: Từ Monitor, Detection đến Digital
  forensics và Recovery kết hợp Mini-SOAR Engine bằng Python theo kiến trúc bảo
  mật 6 lớp giúp tự động hóa toàn bộ quy trình.
visibility: PUBLIC
---
# CHƯƠNG 8.5 : BÁO CÁO THỰC TẾ - INCIDENT RESPONSE REPORT

**Mã sự cố:** IR-2026-RANSOM-001

**Ngày báo cáo:** 06/02/2026

**Mức độ nghiêm trọng:** Critical

**Người thực hiện:** Bùi Nhật Thành - Intern Soc tier 1

### 1. Tổng quan sự cố

Vào lúc 14:00, hệ thống giám sát an ninh đã kích hoạt cảnh báo mức độ cao liên quan đến máy trạm thuộc bộ phận Tài chính là finacal\_01.

Qua phân tích, đội ngũ SOC xác định đây là một cuộc tấn công Ransomware có chủ đích, sử dụng kỹ thuật "Living-off-the-Land" thông qua cấu hình lỗi ở dịch vụ WinRM. Nhờ cơ chế SOAR, cuộc tấn công đã bị ngăn chặn ở giai đoạn đầu, tuy nhiên kẻ tấn công đã kịp mã hóa một số tệp tin thử nghiệm.

### 2. Dòng thời gian & phân tích kỹ thuật

Dưới đây là chi tiết các bước tấn công của Hacker và cách hệ thống phòng thủ ghi nhận:

**13:50:00 - Reconnaissance**

* **Hành vi:** Kẻ tấn công từ IP 10.10.10.130 thực hiện quét cổng nhắm vào máy nạn nhân.

* **Phát hiện:** Suricata IDS phát hiện lưu lượng quét cổng Nmap.

* **Log Evidence:**

  > ```plaintext
  > source="/var/log/vector/zeek_filter_traffic.json" 
  > | search conn_state IN ("S0", "REJ", "RSTR", "RSTO") 
  > | stats count dc(id.resp_p) as distinct_ports by id.orig_h id.resp_h
  > | where distinct_ports > 10
  > | rename id.orig_h as "Scanner IP", id.resp_h as "Target IP", distinct_ports as "Ports Scanned"
  > | sort - "Ports Scanned"
  > ```

<Image src="https://cdn.hashnode.com/res/hashnode/image/upload/v1765095293724/163a71d2-3cbd-4fab-a030-392817f47ce3.png" alt="" align="center" fullwidth="true" />

**13:55:00 - Credential Access**

* **Hành vi:** Kẻ tấn công sử dụng công cụ Hydra để thực hiện Brute-force mật khẩu tài khoản Admin qua giao thức SMB/WinRM.

* **Phát hiện :** Splunk ghi nhận sự gia tăng đột biến của Event ID 4625 trong thời gian ngắn.

* **Log Evidence:**

  > ```plaintext
  > source="/var/log/vector/winlogbeat-debug.json" event.code=4625
  > | search winlog.event_data.IpAddress!="127.0.0.1" AND winlog.event_data.IpAddress!="::1" AND winlog.event_data.IpAddress!="-"
  > | timechart limit=10 useother=f count AS "Failed_Login_Attempts" BY winlog.event_data.IpAddress
  > ```

<Image src="https://cdn.hashnode.com/res/hashnode/image/upload/v1770437693581/ee368c26-1104-43a4-af69-db40827a804d.png" alt="" align="center" fullwidth="true" />

**13:56:00 - Initial Access & Execution**

* **Hành vi:** Kẻ tấn công đoán đúng mật khẩu, đăng nhập thành công event ID 4624. Ngay sau đó, một phiên PowerShell từ xa được thiết lập thông qua tiến trình wsmprovhost.exe.

* **Phát hiện :** Sysmon ghi nhận một loạt Event ID 1 với command line đáng ngờ.

* **Log Evidence:**

  SPL

  ```plaintext
  index=* source="/var/log/vector/winlogbeat-debug.json" 
  | spath 
  | search (event.code="1" OR event.code="4104")
  | search (
      winlog.event_data.CommandLine="*exit*" OR 
      winlog.event_data.ScriptBlockText="*exit*" OR
      winlog.event_data.CommandLine="*whoami*" OR 
      winlog.event_data.CommandLine="*ls *" OR 
      winlog.event_data.CommandLine="*cd *" OR 
      winlog.event_data.CommandLine="*cat *"
  )
  | eval raw_cmd=lower(coalesce('winlog.event_data.CommandLine', 'winlog.event_data.ScriptBlockText'))
  | eval cmd_type=case(
      like(raw_cmd, "%whoami%"), "Recon (whoami)",
      like(raw_cmd, "%exit%"), "Defense Evasion (exit)",
      like(raw_cmd, "%ls %"), "Discovery (ls)",
      like(raw_cmd, "%cd %"), "Navigation (cd)",
      like(raw_cmd, "%cat %"), "Collection (cat)",
      1=1, "Other"
  )
  | timechart span=10m count by cmd_type
  ```

<Image src="https://cdn.hashnode.com/res/hashnode/image/upload/v1770439696548/d796b6c8-60cc-4811-b1d8-08527ab9e046.png" alt="" align="center" fullwidth="true" />

**13:57:00 - SOAR Triggered**

Ngay khi Splunk tương quan được chuỗi sự kiện: Brute Force Success + Suspicious PowerShell, Playbook phản ứng tự động đã được kích hoạt:

1. **Network Containment:** Firewall tự động Block IP 10.10.10.130.

2. **Process Termination:** Gửi lệnh Kill Process ID của powershell.exe.

3. **Isolation:** Cách ly máy trạm khỏi mạng nội bộ .

   <Image src="https://cdn.hashnode.com/res/hashnode/image/upload/v1770798488618/0641d260-f70e-44a3-a53d-dbd72fd41c56.png" align="center" fullwidth="false" />

### 3. Điều tra số và khôi phục

Mặc dù tấn công đã bị chặn, một số file dữ liệu secret.docx đã bị mã hóa thành secret.docx.encrypted. Thay vì trả tiền chuộc, quy trình khôi phục sau đã được thực hiện:

**Bước 1: Thu thập chứng cứ**

Sử dụng công cụ FTK Imager để trích xuất toàn bộ bộ nhớ RAM của máy nạn nhân ngay thời điểm sự cố, nhằm bảo toàn dữ liệu biến đổi.

**Bước 2: Phân tích bộ nhớ**

Sử dụng EZ tools để tìm kiếm tiến trình PowerShell chưa kịp tắt hẳn trong RAM.

* **Mục tiêu:** Tìm kiếm biến $Key và $IV mà script mã độc sử dụng.

* **Kết quả:** Đã tìm thấy chuỗi khóa AES-256 dạng Base64 nằm trong vùng nhớ heap của process.

**Bước 3: Giải mã**

Viết script giải mã sử dụng Key vừa tìm được để khôi phục dữ liệu gốc.

### 4. Chỉ số IOCs

Đây là các dấu hiệu nhận biết cuộc tấn công này, dùng để cấu hình chặn trên các hệ thống bảo mật khác:

| **Loại**             | **Giá trị**                                                      | **Mô tả**                                 |
| -------------------- | ---------------------------------------------------------------- | ----------------------------------------- |
| **Attacker IP**      | 10.10.10.130                                                     | IP nguồn thực hiện Brute-force & C2       |
| **Hash SHA256**      | 06d6f44c7aad76800b1319b86a3153da07bddd158f0a6aaf07ec5a237ac811ab | File thực thi mã độc encrypt.ps1          |
| **Network Artifact** | Port 5985, 5986                                                  | Giao thức WinRM bị lạm dụng               |
| **Process Name**     | wsmprovhost.exe                                                  | Tiến trình cha sinh ra PowerShell độc hại |

### 5. Khuyến nghị bảo mật

Dựa trên kết quả điều tra, tôi đề xuất các biện pháp khắc phục sau:

1. **Vô hiệu hóa WinRM Public:** Chỉ cho phép WinRM hoạt động trong mạng Management VLAN, chặn truy cập từ Internet hoặc mạng người dùng thường.

2. **Siết chặt chính sách mật khẩu:** Áp dụng Account Lockout Policy tạo ra cơ chế khóa đăng nhập sau số lần đăng nhập sai nhất định để chống Brute-force.

3. **Giám sát PowerShell:** Bật tính năng Event ID 4104 trên toàn bộ máy trạm để phát hiện các đoạn mã thực thi trong bộ nhớ.

4. **Triển khai SOAR:** Tiếp tục mở rộng các Playbook tự động hóa để MTTR cho các kịch bản tấn công khác.
