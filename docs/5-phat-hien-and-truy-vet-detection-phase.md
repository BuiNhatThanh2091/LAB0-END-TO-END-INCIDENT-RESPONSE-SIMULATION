---
title: 'End-to-End Incident Response Simulation: From Detection to Recovery'
label: 'CHƯƠNG 5: PHÁT HIỆN & TRUY VẾT'
slug: 5-phat-hien-and-truy-vet-detection-phase
description: >-
  Dự án mô phỏng quy trình SOC khép kín: Từ Monitor, Detection đến Digital
  forensics và Recovery kết hợp Mini-SOAR Engine bằng Python theo kiến trúc bảo
  mật 6 lớp giúp tự động hóa toàn bộ quy trình.
visibility: PUBLIC
---
# CHƯƠNG 5: CHIẾN LƯỢC PHÁT HIỆN & SĂN TÌM MỐI ĐE DỌA

Dựa trên các TTPs đã được Kẻ tấn công thực hiện trong Chương 4, em đã xây dựng các quy tắc phát hiện chuyên sâu. Chiến lược giám sát được thực hiện đa tầng: từ Metadata mạng : Zeek/Suricata đến hành vi chi tiết tại Endpoint : Sysmon/Winlogbeat.

Các truy vấn dưới đây được viết bằng ngôn ngữ SPL trên Splunk, đóng vai trò là "Logic cốt lõi" để module SOAR tham chiếu và ra quyết định chặn.

## 5.1. GIÁM SÁT TẦNG MẠNG

**Source:** Zeek\
**Log Location:** /var/log/vector/zeek\_filter\_traffic.json

Link github tài nguyên về Network logs: [network\_forensics](https://github.com/BuiNhatThanh2091/LAB0-END-TO-END-INCIDENT-RESPONSE-SIMULATION/tree/main/evidence/network_forensics)

### A. Phát hiện Trinh sát & Dò quét

*Mapped to MITRE ATT\&CK:* ***T1595 (Active Scanning)***

**1. Port Scanning Anomaly**

* **Logic phát hiện:** Kẻ tấn công thường tạo ra lượng lớn kết nối thất bại (Flag S0, REJ) trong thời gian ngắn để tìm cổng mở. Truy vấn thống kê các IP nguồn kết nối tới >10 cổng đích khác nhau mà không thành công.

* **Splunk SPL:**

  ```plaintext
  source="/var/log/vector/zeek_filter_traffic.json" 
  | search conn_state IN ("S0", "REJ", "RSTR", "RSTO") 
  | stats count dc(id.resp_p) as distinct_ports by id.orig_h id.resp_h
  | where distinct_ports > 10
  | rename id.orig_h as "Scanner IP", id.resp_h as "Target IP", distinct_ports as "Ports Scanned"
  | sort - "Ports Scanned"
  ```

<Image src="https://cdn.hashnode.com/res/hashnode/image/upload/v1765095293724/163a71d2-3cbd-4fab-a030-392817f47ce3.png" alt="" align="center" fullwidth="true" />

Link github : [Detect\_Port\_Scanning.csv](https://github.com/BuiNhatThanh2091/LAB0-END-TO-END-INCIDENT-RESPONSE-SIMULATION/blob/main/evidence/network_forensics/Detect_Port_Scanning.csv)

**2. Service Enumeration (Định danh dịch vụ)**

**Logic phát hiện:** Sau khi quét cổng, kẻ tấn công thực hiện kết nối đầy đủ (Flag SF) tới các dịch vụ Web (8080) hoặc Mail (8025) để xác định phiên bản phần mềm.

SPL

```plaintext
source="/var/log/vector/zeek_filter_traffic.json" 
| search id.resp_p IN (8080, 8025) conn_state="SF"
| stats count sum(orig_bytes) as Upload_Bytes sum(resp_bytes) as Download_Bytes values(service) as Service by id.orig_h id.resp_h id.resp_p
| eval Upload_KB=round(Upload_Bytes/1024, 2), Download_KB=round(Download_Bytes/1024, 2)
| table id.orig_h id.resp_h id.resp_p Service Upload_KB Download_KB
```

<Image src="https://cdn.hashnode.com/res/hashnode/image/upload/v1765095335789/272859aa-ace2-4ee7-9574-7458054a032e.png" alt="" align="center" fullwidth="true" />

Link github : [Service\_Enumeration.csv](https://github.com/BuiNhatThanh2091/LAB0-END-TO-END-INCIDENT-RESPONSE-SIMULATION/blob/main/evidence/network_forensics/Service_Enumeration.csv)

### B. Phát hiện Xâm nhập & Di chuyển ngang

*Mapped to MITRE ATT\&CK:* ***T1021.006 (Windows Remote Management)***

**3. WinRM Exploitation Analysis**

* **Logic phát hiện:** Giao thức WinRM (Port 5985) thường chỉ dùng cho quản trị nội bộ. Kết nối từ ngoài vào có thời lượng dài (>10s) hoặc truyền tải dữ liệu lớn (>5MB) là dấu hiệu của Data Exfiltration.

SPL

```plaintext
source="/var/log/vector/zeek_filter_traffic.json" id.resp_p=5985
| eval connection_type=case(
    duration > 10, "Long Lived Session (Interactive Shell)", 
    resp_bytes > 5000, "Large Data Transfer (Exfiltration/Payload)", 
    true(), "Normal Keep-Alive"
)
| search connection_type != "Normal Keep-Alive"
| table _time id.orig_h id.resp_h duration orig_bytes resp_bytes history connection_type uid
| sort - duration
```

<Image src="https://cdn.hashnode.com/res/hashnode/image/upload/v1765095376688/af24b509-5c0f-497b-8744-9e2c2916ccc6.png" alt="" align="center" fullwidth="true" />

Link github : [WinRM\_Exploitation.csv](https://github.com/BuiNhatThanh2091/LAB0-END-TO-END-INCIDENT-RESPONSE-SIMULATION/blob/main/evidence/network_forensics/WinRM_Exploitation.csv)

**4. TCP Flags History**

**Logic phát hiện:** Phân tích cờ TCP trong trường history của Zeek để xác nhận dữ liệu thực sự được truyền tải (Có cờ 'D' - Data) hay chỉ là bắt tay ba bước rồi ngắt.

SPL

```plaintext
source="/var/log/vector/zeek_filter_traffic.json" id.resp_p=5985
| stats count by history
| eval description=case(
    history LIKE "%D%", "Data Payload Transferred (Confirmed)",
    history LIKE "%R%", "Connection Reset (Aborted)",
    history="ShADad", "Handshake -> Data -> Fin (Standard Transfer)"
)
```

<Image src="https://cdn.hashnode.com/res/hashnode/image/upload/v1765095420680/4ff10c91-cf08-498a-8de9-b0cad0104f6f.png" alt="" align="center" fullwidth="true" />

Link github : [TCP\_Flags\_History.csv](https://github.com/BuiNhatThanh2091/LAB0-END-TO-END-INCIDENT-RESPONSE-SIMULATION/blob/main/evidence/network_forensics/TCP_Flags_History.csvhttps://github.com/BuiNhatThanh2091/LAB0-END-TO-END-INCIDENT-RESPONSE-SIMULATION/blob/main/evidence/network_forensics/TCP_Flags_History.csv)

## 5.2. HỆ THỐNG CẢNH BÁO XÂM NHẬP (IDS ALERTING)

**Telemetry Source:** Suricata\
**Log Location:** /var/log/vector/suricata\_traffic.json

Mục tiêu: Định danh tấn công dựa trên bộ luật (Signature-based Detection).

Link github tài nguyên của Suricata : [ids\_alerting](https://github.com/BuiNhatThanh2091/LAB0-END-TO-END-INCIDENT-RESPONSE-SIMULATION/tree/main/evidence/ids_alerting)

**5. Evil-WinRM Detection (T1190)**

* **Logic phát hiện:** Công cụ Evil-WinRM để lại User-Agent đặc trưng Microsoft WinRM Client khi thực hiện kết nối HTTP.

SPL

```plaintext
source="/var/log/vector/suricata_traffic.json" dest_port=5985 app_proto=http
| search http.http_user_agent="Microsoft WinRM Client" OR alert.signature="*WINRM*"
| stats count values(alert.signature) as Signatures values(http.http_method) as Methods by src_ip dest_ip
| rename src_ip as "Attacker", dest_ip as "Victim"
```

<Image src="https://cdn.hashnode.com/res/hashnode/image/upload/v1765095642295/ec67e792-899b-410c-9cdd-4d4099585007.png" alt="" align="center" fullwidth="true" />

Link github : [Exploitation.csv](https://github.com/BuiNhatThanh2091/LAB0-END-TO-END-INCIDENT-RESPONSE-SIMULATION/blob/main/evidence/ids_alerting/Exploitation.csv)

**6. Signature-based Timeline Analysis**

**Mục tiêu:** Dựng lại dòng thời gian tấn công (Attack Timeline) bằng cách nhóm các cảnh báo theo giai đoạn Cyber Kill Chain.

**Splunk SPL:**

* ```plaintext
  source="/var/log/vector/suricata_traffic.json"
  | eval Phase=case(
      like(lower('alert.signature'), "%scan%") OR like(lower('alert.signature'), "%recon%"), "1. Reconnaissance",
      like(lower('alert.signature'), "%mailhog%") OR like(lower('alert.signature'), "%python%") OR dest_port IN (8025, 8080), "2. Enumeration",
      like(lower('http.http_user_agent'), "%winrm%") OR dest_port=5985, "3. Lateral Movement (WinRM)"
  )
  | search Phase=*
  | timechart span=5m count by Phase
  ```

<Image src="https://cdn.hashnode.com/res/hashnode/image/upload/v1765095757034/907f3e9d-5d26-47fc-9c7d-82907dbc3b47.png" alt="" align="center" fullwidth="true" />

Link github : [Attack\_Timeline\_Dashboard.csv](https://github.com/BuiNhatThanh2091/LAB0-END-TO-END-INCIDENT-RESPONSE-SIMULATION/blob/main/evidence/ids_alerting/Attack_Timeline_Dashboard.csv)

**7. Quick IP Check**

Query nhanh để liệt kê các IP đang tương tác với port 5985 và trả về nếu khớp với Signature-based Detection của suricata.

SPL

```plaintext
index=* source="/var/log/vector/suricata_traffic.json" 
| spath 
| search dest_port=5985 
| table _time, src_ip, dest_ip, alert.signature
```

<Image src="https://cdn.hashnode.com/res/hashnode/image/upload/v1765095817892/5bf9931a-e5c4-4c47-a7cf-4da988030c93.png" alt="" align="center" fullwidth="true" />

Link github : [Quick\_IP\_Check.csv](https://github.com/BuiNhatThanh2091/LAB0-END-TO-END-INCIDENT-RESPONSE-SIMULATION/blob/main/evidence/ids_alerting/Quick_IP_Check.csv)

## 5.3. GIÁM SÁT TẦNG ENDPOINT

**Telemetry Source:** Winlogbeat\
**Log Location:** /var/log/vector/winlogbeat-debug.json

Đây là lớp giám sát cuối cùng, nơi ghi nhận các hành vi thực thi mã độc "Fileless" mà Network Layer có thể bỏ qua.\
tài nguyên logs: [endpoint\_dectection](https://github.com/BuiNhatThanh2091/LAB0-END-TO-END-INCIDENT-RESPONSE-SIMULATION/tree/main/evidence/endpoint_dectection)

### A. Defense Evasion & Discovery

*Mapped to MITRE ATT\&CK:* ***T1059.001 (PowerShell), T1082 (System Info Discovery)***

**8. PowerShell Execution Policy Bypass**

* **Logic phát hiện:** Tìm kiếm các chuỗi lệnh chứa cờ -enc ( Thường dùng để giấu payload Base64) hoặc bypass.

SPL

```plaintext
index=* source="/var/log/vector/winlogbeat-debug.json" 
| spath 
| search (event.code="4688" OR event.code="4104") 
| search (
    winlog.event_data.CommandLine="*bypass*" OR 
    winlog.event_data.CommandLine="*-enc*" OR 
    winlog.event_data.CommandLine="*-encodedcommand*" OR
    winlog.event_data.ScriptBlockText="*bypass*"
)
| table _time, "host.name", "user.name", event.code, "winlog.event_data.CommandLine", "winlog.event_data.ScriptBlockText"
```

<Image src="https://cdn.hashnode.com/res/hashnode/image/upload/v1765095877104/1e43f617-a564-44e9-bff6-22346924c7c7.png" alt="" align="center" fullwidth="true" />

Link github : [Security\_Bypass.csv](https://github.com/BuiNhatThanh2091/LAB0-END-TO-END-INCIDENT-RESPONSE-SIMULATION/blob/main/evidence/endpoint_dectection/Security_Bypass.csv)

**9. Post-Exploitation Discovery Commands**

* **Logic phát hiện:** Phát hiện chuỗi lệnh trinh sát nội bộ (whoami, ls, cat) được thực thi ngay sau khi thiết lập phiên WinRM.

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
| table _time, event.code, "host.name", "winlog.event_data.CommandLine", "winlog.event_data.ScriptBlockText"
| sort _time
```

<Image src="https://cdn.hashnode.com/res/hashnode/image/upload/v1765095942615/7e622e8a-6d3b-45a5-914f-cddd8fc732e6.png" alt="" align="center" fullwidth="true" />

Link github : [System\_Discovery.csv](https://github.com/BuiNhatThanh2091/LAB0-END-TO-END-INCIDENT-RESPONSE-SIMULATION/blob/main/evidence/endpoint_dectection/System_Discovery.csv)

### B. Payload Delivery & Impact

*Mapped to MITRE ATT\&CK:* ***T1486 (Data Encrypted for Impact), T1041 (Exfiltration)***

**10. Malicious Artifacts & Ransomware Behavior**

* **Logic phát hiện:** Đây là truy vấn quan trọng nhất. Nó kết hợp nhiều sự kiện để vẽ nên bức tranh toàn cảnh:

  * Event 4624 : Đăng nhập qua mạng WinRM.

  * Event 1: Tiến trình wsmprovhost.exe sinh ra tiến trình lạ.

  * Event 4104: Bắt được nội dung script chứa các từ khóa mã hóa (SHA1, Check-Files, encrypt1.ps1) hoặc hành vi exfiltration.

* **Splunk SPL:**

SPL

```plaintext
index=* source="/var/log/vector/winlogbeat-debug.json" 
| spath 
| search 
    (event.code="4624" AND winlog.event_data.LogonType="3" AND winlog.event_data.IpAddress="10.10.10.130") OR 
    (event.code="1" AND winlog.event_data.Image="*wsmprovhost.exe") OR 
    (event.code="11" AND winlog.event_data.Image="*wsmprovhost.exe") OR 
    (event.code="4104" AND (
        winlog.event_data.ScriptBlockText="*encrypt1.ps1*" OR 
        winlog.event_data.ScriptBlockText="*Get-SHA1Sum*" OR 
        winlog.event_data.ScriptBlockText="*Check-Files*" OR 
        winlog.event_data.ScriptBlockText="*System.Security.Cryptography.SHA1*" OR 
        winlog.event_data.ScriptBlockText="*ConvertTo-Csv*" OR
        winlog.event_data.ScriptBlockText="*Unresolve-Path*" OR
        winlog.event_data.ScriptBlockText="*Cleanup*" OR
        winlog.event_data.ScriptBlockText="*LASTEXITCODE*"
    ))
| eval Activity_Type = case(
    match('event.code', "4624"), "1. Attacker Logon (WinRM)", 
    match('event.code', "1"), "2. WinRM Process Spawned", 
    match('event.code', "11"), "3. WinRM Dropped File",
    match('event.code', "4104"), "4. Malicious Script Execution"
)
| table _time, Activity_Type, "host.name", "user.name", "winlog.event_data.IpAddress", "winlog.event_data.Image", "winlog.event_data.TargetFilename", "winlog.event_data.ScriptBlockText"
| sort _time
```

<Image src="https://cdn.hashnode.com/res/hashnode/image/upload/v1765096002637/45e16bd5-ed53-4938-808b-5db624d06d29.png" alt="" align="center" fullwidth="true" />

Link github : [Malicious\_File\_Upload.csv](https://github.com/BuiNhatThanh2091/LAB0-END-TO-END-INCIDENT-RESPONSE-SIMULATION/blob/main/evidence/endpoint_dectection/Malicious_File_Upload.csv)

**11. Download file**

Phát hiện hành vi convert dữ liệu sang Base64 : ToBase64String để tuồn ra ngoài, kết hợp lọc nhiễu .

SPL

```plaintext
index=* source="/var/log/vector/winlogbeat-debug.json" 
| spath 
| search 
    (event.code="4624" AND winlog.event_data.LogonType="3" AND winlog.event_data.IpAddress="10.10.10.130") OR 
    (event.code="1" AND (
        winlog.event_data.Image="*wsmprovhost.exe" OR 
        winlog.event_data.Image="*clipesu.exe" OR 
        winlog.event_data.Image="*ClipESUConsumer.exe" OR
        winlog.event_data.Image="*DeviceCensus.exe"
    )) OR 
    (event.code="11" AND winlog.event_data.Image="*wsmprovhost.exe") OR 
    (event.code="4104" AND (
        winlog.event_data.ScriptBlockText="*encrypt1.ps1*" OR 
        winlog.event_data.ScriptBlockText="*Get-SHA1Sum*" OR 
        winlog.event_data.ScriptBlockText="*Check-Files*" OR 
        winlog.event_data.ScriptBlockText="*System.Security.Cryptography.SHA1*" OR 
        winlog.event_data.ScriptBlockText="*ConvertTo-Csv*" OR
        winlog.event_data.ScriptBlockText="*Unresolve-Path*" OR
        winlog.event_data.ScriptBlockText="*Cleanup*" OR
        winlog.event_data.ScriptBlockText="*LASTEXITCODE*" OR
        winlog.event_data.ScriptBlockText="*data_important*" OR
        winlog.event_data.ScriptBlockText="*ToBase64String*" OR
        winlog.event_data.ScriptBlockText="*OpenRead*"
    ))
| eval Activity_Type = case(
    match('event.code', "4624"), "1. Attacker Logon (WinRM)", 
    match('event.code', "1") AND like('winlog.event_data.Image', "%wsmprovhost.exe"), "2. WinRM Process Spawned",
    match('event.code', "1") AND (like('winlog.event_data.Image', "%clipesu%") OR like('winlog.event_data.Image', "%DeviceCensus%")), "2b. System Process (Noise/Telemetry)",
    match('event.code', "11"), "3. WinRM Dropped File",
    match('event.code', "4104") AND like('winlog.event_data.ScriptBlockText', "%ToBase64String%"), "4b. Data Exfiltration/Encoding",
    match('event.code', "4104"), "4a. Malicious Script Execution"
)
| table _time, Activity_Type, "host.name", "user.name", "winlog.event_data.IpAddress", "winlog.event_data.Image", "winlog.event_data.TargetFilename", "winlog.event_data.ScriptBlockText"
| sort _time
```

<Image src="https://cdn.hashnode.com/res/hashnode/image/upload/v1765096058724/1bf84f69-5014-4136-887d-4515aa544da9.png" alt="" align="center" fullwidth="true" />

Link github : [Data\_Exfiltration.csv](https://github.com/BuiNhatThanh2091/LAB0-END-TO-END-INCIDENT-RESPONSE-SIMULATION/blob/main/evidence/endpoint_dectection/Data_Exfiltration.csv)

**12. Sensitive Data Access**

**Logic phát hiện:** Kiểm toán việc truy cập trái phép vào tệp tin mục tiêu : data\_important.txt thông qua sự kiện Object Access ID 4663.

SPL

```plaintext
index=* source="/var/log/vector/winlogbeat-debug.json" 
| spath 
| search event.code="4663" 
| search winlog.event_data.AccessMask="0x1" 
| search NOT ("winlog.event_data.ProcessName"="*svchost.exe*" OR "winlog.event_data.ProcessName"="*MsMpEng.exe*")
| table _time, "host.name", "user.name", "winlog.event_data.ProcessName", "winlog.event_data.ObjectName", "winlog.event_data.AccessMask"
```

<Image src="https://cdn.hashnode.com/res/hashnode/image/upload/v1765096204025/0000c78d-b91b-429e-82bc-7d4b2f2d335b.png" alt="" align="center" fullwidth="true" />

Link github : [Object\_Access\_Audit.csv](https://github.com/BuiNhatThanh2091/LAB0-END-TO-END-INCIDENT-RESPONSE-SIMULATION/blob/main/evidence/endpoint_dectection/Object_Access_Audit.csv)

### **Tài Nguyên:**

Link github đến Logs : [evidence](https://github.com/BuiNhatThanh2091/LAB0-END-TO-END-INCIDENT-RESPONSE-SIMULATION/tree/main/evidence)
