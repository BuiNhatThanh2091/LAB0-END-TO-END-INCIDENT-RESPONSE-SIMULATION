---
title: 'End-to-End Incident Response Simulation: From Detection to Recovery'
label: 'CHƯƠNG 3: TRIỂN KHAI HỆ THỐNG '
slug: trien-khai-he-thong-implementation
description: >-
  Dự án mô phỏng quy trình SOC khép kín: Từ Monitor, Detection đến Digital
  forensics và Recovery kết hợp Mini-SOAR Engine bằng Python theo kiến trúc bảo
  mật 6 lớp giúp tự động hóa toàn bộ quy trình.
visibility: PUBLIC
---
# CHƯƠNG 3. TRIỂN KHAI HỆ THỐNG

Trong giai đoạn này, dự án thiết lập hạ tầng Cyber Range mô phỏng mạng doanh nghiệp thu nhỏ. Kiến trúc đảm bảo tính phân tách giữa vùng người dùng, vùng giám sát và vùng tấn công.

## 1. CẤU TRÚC HỆ THỐNG

### A. SƠ ĐỒ & QUY HOẠCH MẠNG

* **Network Segment:** 10.10.10.0/24.

* **Connectivity:** Đảm bảo kết nối thông suốt giữa các node để phục vụ luồng Log và luồng Tấn công .

| **Hostname**      | **Role**     | **OS**       | **IP Address** | **Chức năng chính**                                                                         |
| ----------------- | ------------ | ------------ | -------------- | ------------------------------------------------------------------------------------------- |
| **Ubuntu-Server** | **SOC Core** | Ubuntu 24.04 | 10.10.10.128   | **Security Gateway:** Chứa SIEM, NIDS, Log Pipeline và SOAR Engine.                         |
| **Win10-Victim**  | **Endpoint** | Windows 10   | 10.10.10.129   | **High-Value Asset:** Máy trạm chứa dữ liệu nhạy cảm, được gắn các sensor giám sát hành vi. |
| **Kali-Attacker** | **Red Team** | Kali Linux   | 10.10.10.130   | **Threat Simulator:** Thực hiện các kỹ thuật tấn công .                                     |

### B. Sơ đồ hệ thống

<Image src="https://cdn.hashnode.com/res/hashnode/image/upload/v1770775673579/17d6e881-7272-478b-8cd2-a65bde01eaaa.png" alt="" align="center" fullwidth="true" />

## 2. CẤU HÌNH ENDPOINT

***Mục tiêu: Biến máy trạm thông thường thành một Sensor có khả năng ghi nhận chi tiết mọi hành vi bất thường.***

### A. Environment Baseline

**Security Posture Adjustment:**

* **Disable Windows Defender**: Mô phỏng tình huống Endpoint chưa được cập nhật Signature hoặc bị Bypass bởi kỹ thuật Obfuscation.

  **Disable UAC**: Mô phỏng người dùng có thói quen cấp quyền Administrator bừa bãi, tạo điều kiện cho Script thực thi quyền cao nhất.

### B. Telemetry Standardization

Sử dụng Sysmon để mở rộng khả năng giám sát của Windows Event Log, kết hợp với Winlogbeat để lọc và chuyển tiếp log về trung tâm.

Log Filtering Strategy\*\*:\*\* Áp dụng bộ lọc ngay tại nguồn để loại bỏ log rác, giảm tải cho đường truyền và SIEM.

**Winlogbeat.yml:**

YAML

```plaintext
winlogbeat.event_logs:
  - name: Microsoft-Windows-Sysmon/Operational
    event_id: 1, 3, 11, 22        # Process Create, Network Conn, File Create, DNS Query
    ignore_older: 4h

  - name: Microsoft-Windows-PowerShell/Operational
    event_id: 4104                # Script Block Logging (Critical for Fileless Malware)
    ignore_older: 4h

  - name: Security
    event_id: 4624, 4625, 4663    # Logon Success/Fail, Object Access
    ignore_older: 4h

processors:
  - drop_event:
      when:
        and:
          - equals:
              winlog.event_id: 4663
          - not: # Chỉ giữ lại log truy cập vào file quan trọng cụ thể
              equals:
                winlog.event_data.ObjectName: "C:\\Users\\Thanh\\Desktop\\Day_la_du_lieu_quan_trong.txt"
```

Link: [winlogbeat.yml](https://github.com/BuiNhatThanh2091/LAB0-END-TO-END-INCIDENT-RESPONSE-SIMULATION/blob/main/configs/winlogbeat.yml)

### C. Data Integrity Monitoring

Thiết lập chính sách kiểm soát truy cập SACL để phát hiện hành vi đọc/ghi/xóa trái phép trên tài liệu mật.

* **Target Asset:** C:\Program Files\data\_important.txt

* **Policy Enforcement:**

  1. **Local Security Policy:** Enable Audit File System.

  2. **File Attribute Auditing:** Cấu hình Audit cho nhóm Everyone với các quyền Write, Append Data, Delete.

* **Outcome:** Mọi tác động lên file sẽ sinh ra Event ID 4663, đóng vai trò là "Trigger" cho hệ thống cảnh báo.

* <Image src="https://cdn.hashnode.com/res/hashnode/image/upload/v1764747252408/1050a85c-2bea-4651-8133-5c961a253634.png" alt="" align="left" fullwidth="true" />

## 3. HẠ TẦNG TẤN CÔNG MẠNG

### A. Offensive Toolset

* **Hydra:** Cấu hình tấn công Brute-force tối ưu hóa tốc độ để kiểm thử độ mạnh mật khẩu và khả năng phát hiện "Failed Logon" của SIEM.

* **Evil-WinRM:** Sử dụng giao thức quản trị WinRM để điều khiển máy nạn nhân, né tránh việc tạo ra các kết nối TCP lạ.

### B. Payload Artifact

Phát triển script PowerShell ([`encrypt.ps1`](https://github.com/BuiNhatThanh2091/LAB0-END-TO-END-INCIDENT-RESPONSE-SIMULATION/blob/main/scripts/attacker_sim/encrypt.ps1)) mô phỏng hành vi của Ransomware hiện đại thay vì sử dụng mẫu mã độc thực tế (tránh rủi ro lây nhiễm chéo).

* **Cơ chế hoạt động:**

  1. Sinh khóa AES & IV ngẫu nhiên.

  2. Đọc dữ liệu mục tiêu -> Mã hóa AES-256 -> Ghi đè file gốc.

  3. Không giao tiếp ra ngoài (để kiểm thử khả năng phát hiện hành vi cục bộ).

**Payload Code:**

PowerShell

```plaintext
param (
    [string]$Path = "C:\Program Files\data_important.txt",
    [string]$KeyBase64 = "xIs9zA+U1j2/qW4b5r6t7y8u9i0o1p2a3s4d5f6g7h8=", 
    [string]$IVBase64  = "1a2b3c4d5e6f7g8h9i0j1k=="
)
try {
    if (-not (Test-Path $Path)) { throw "Target missing" }
    # ... Encryption Logic Implemented Here ...
```

## 4. HẠ TÂNG GIÁM SÁT

Máy chủ này đóng vai trò Security Gateway, nơi hội tụ mọi dòng chảy dữ liệu.

### A. Network Detection & Response : Suricata IDS

Triển khai Suricata ở chế độ IDS để bắt các dấu hiệu tấn công dựa trên Signature-based.

* \*\*Custom Ruleset (\*\*local.rules): Tối ưu hóa bộ luật để giảm False Positive, tập trung vào các hành vi đặc thù của kịch bản.

  * Reconnaissance: Phát hiện Nmap Scan, Ping Sweep.

  * Lateral Movement: Phát hiện traffic WinRM và Python HTTP Server .

**Detection Logic Snippet:**

Bash

```plaintext
# Detect Python HTTP Server (Used for payload delivery)
alert http $HOME_NET any -> $HOME_NET 8080 ( \
    msg:"THREAT: Python http.server Access Detected"; \
    flow:to_server,established; \
    sid:1007201; rev:5; \
)
```

### B. Network Forensics : Zeek

Sử dụng Zeek làm giám sát mạng, ghi lại Metadata của mọi kết nối . Các log quan trọng: conn.log.

### C. Data Pipeline : Vector

Sử dụng Vector làm lớp trung gian để chuẩn hóa dữ liệu.

* **Workflow:** Source (Zeek/Suricata/Winlogbeat) -> Lọc nhiễu/Rename Fields -> Splunk.

* **Lợi ích:** Giảm tải xử lý cho Splunk và đảm bảo định dạng log thống nhất.

### D. SIEM & Analytics

Nơi lưu trữ tập trung và hiển thị Dashboard. Splunk nhận dữ liệu sạch từ Vector để phục vụ cho việc Alerting và Threat Hunting.

## 5. PHẢN ỨNG VÀ TỰ ĐỘNG HÓA

***Đây là thành phần nâng cao giúp hiện đại hóa quy trình SOC, chuyển từ thụ động sang chủ động.***

### A. Kiến trúc Module

Hệ thống SOAR được phát triển bằng Python, triển khai trực tiếp trên Ubuntu Server, hoạt động như một dịch vụ nền.

* **Vị trí:** Nằm tại vị trí sau SPL, giao tiếp hai chiều với SIEM và Hạ tầng mạng/Endpoint .

* **Cấu trúc mã nguồn:**

  * [`ingestion.py`](https://github.com/BuiNhatThanh2091/LAB0-END-TO-END-INCIDENT-RESPONSE-SIMULATION/blob/main/scripts/response_auto/ingestion.py): Module kết nối API với Splunk để truy vấn các cảnh báo "Critical".

  * [`scoring.py`](https://github.com/BuiNhatThanh2091/LAB0-END-TO-END-INCIDENT-RESPONSE-SIMULATION/blob/main/scripts/response_auto/scoring.py): Engine chấm điểm rủi ro để quyết định mức độ nghiêm trọng.

  * [`response.py`](https://github.com/BuiNhatThanh2091/LAB0-END-TO-END-INCIDENT-RESPONSE-SIMULATION/blob/main/scripts/response_auto/response.py): Module thực thi hành động ngăn chặn.

### B. Logic Vận hành

1. **Polling:** Định kỳ 15 giây, SOAR query Splunk để tìm các IP có hành vi: quét cổng của Suricata hoặc đăng nhập thất bại nhiều lần Event 4625 của security.

2. **Decision Making:** Nếu Risk Score > 100 kích hoạt Playbook chặn.

3. **Active Response:**

   * **Network Level:** Gọi lệnh iptables trên Ubuntu để chặn IP nguồn của kẻ tấn công.

   * **Endpoint Level:** Sử dụng thư viện paramiko để SSH vào máy nạn nhân Windows, thực thi lệnh ngắt kết nối hoặc Kill tiến trình đáng ngờ.

**Automation Workflow Snippet:**

Python

```plaintext
# Pseudo-code logic
if risk_score > THRESHOLD:
    logger.warning(f"Blocking Malicious IP: {attacker_ip}")
    firewall.block_ip(attacker_ip)
    edr_agent.isolate_host(victim_ip)
    notification.send_alert(f"Threat Neutralized: {attacker_ip}")
```
