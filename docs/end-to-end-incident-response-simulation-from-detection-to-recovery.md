---
title: 'End-to-End Incident Response Simulation: From Detection to Recovery'
label: 'CHƯƠNG 1: GIỚI THIỆU DỰ ÁN'
slug: end-to-end-incident-response-simulation-from-detection-to-recovery
description: >-
  Dự án mô phỏng quy trình SOC khép kín: Từ Monitor, Detection đến Digital
  forensics và Recovery kết hợp Mini-SOAR Engine bằng Python theo kiến trúc bảo
  mật 6 lớp giúp tự động hóa toàn bộ quy trình.
visibility: PUBLIC
---
# CHƯƠNG 1. GIỚI THIỆU DỰ ÁN

## 1. MỤC TIÊU DỰ ÁN

Dự án hiện thực hóa kiến thức SOC Level 1 TryHackMe vào môi trường thực chiến giả lập doanh nghiệp Fintech SMB. Thay vì chỉ dừng lại ở việc hiện thực hóa lý thuyết, dự án hướng tới việc xây dựng một Khung năng lực an ninh mạng thực chiến.

Mục tiêu cốt lõi là thiết lập quy trình SOC khép kín, chuẩn hóa từ khâu Giám sát, Phát hiện đến Điều tra số và Khôi phục hệ thống. Đồng thời, dự án bước đầu thử nghiệm tự động hóa phản ứng để hỗ trợ đội ngũ vận hành giảm thiểu thời gian xử lý các tác vụ lặp lại.

## 2. BỐI CẢNH DOANH NGHIỆP

## 2.1. Mô hình giả lập

* **Lĩnh vực:** Công nghệ Tài chính.

* **Quy mô:** Doanh nghiệp vừa và nhỏ với nhân sự từ 50 - 100 người.

* **Đặc thù:** Tốc độ chuyển đổi số nhanh, hạ tầng linh hoạt nhưng ngân sách bảo mật còn hạn chế.

### 2.2. Tài sản trọng yếu

Mục tiêu bảo vệ tối thượng là Tính bảo mật và Tính toàn vẹn của dữ liệu tài chính:

* **Cơ sở dữ liệu Bảng lương & Thuế:** Chứa thông tin định danh cá nhân và dữ liệu nhạy cảm của nhân viên/khách hàng.

* **Máy trạm Kế toán trưởng:** Được xác định là "điểm yếu nhất" trong chuỗi phòng thủ do thường xuyên xử lý file lạ từ email, dễ trở thành cửa ngõ cho mã độc.

### 2.3. Thách thức bảo mật & Rủi ro kinh doanh

* **Ransomware:** Kẻ tấn công không chỉ mã hóa dữ liệu để đòi tiền chuộc mà còn đe dọa phát tán dữ liệu, gây tổn hại uy tín thương hiệu.

* **Kỹ thuật "Living-off-the-Land" :** Hacker lợi dụng công cụ quản trị hợp pháp như WinRM , powershell để ẩn mình, vô hiệu hóa Antivirus truyền thống.

* **Vấn đề vận hành:** Hệ thống cũ rời rạc khiến cảnh báo bị quá tải. Thời gian phản ứng chậm trễ dẫn đến rủi ro bị xâm nhập sâu trước khi kịp ngăn chặn.

## 3. KIẾN TRÚC GIẢI PHÁP & PHẠM VI

Dự án triển khai mô hình phòng thủ chiều sâu kết hợp với một module tự động hóa nhỏ gọn để hỗ trợ phản ứng nhanh.

**Hệ thống phòng thủ bao gồm:**

1. **Splunk:** Điều phối toàn bộ hệ thống, chịu trách nhiệm thu thập log, phân tích tương quan và phát hiện chuỗi tấn công.

2. **Suricata & Zeek:** Giám sát cho hạ tầng mạng, phát hiện bất thường trong luồng traffic và chữ ký tấn công.

3. **Sysmon:** Giám sát sâu hành vi cấp tiến trình, giúp phát hiện các kỹ thuật Fileless Malware.

4. **Mini-SOAR :**

   * Đây là một module Python tùy biến được tích hợp để đóng vai trò người thực thi và kiểm tra cho SOC.

   * **Chức năng:** Hỗ trợ thực thi các tác vụ ngăn chặn tức thời như chặn IP độc hại trên Firewall hoặc ngắt phiên kết nối SSH/WinRM ngay khi điểm rủi ro vượt ngưỡng, giúp giảm tải áp lực cho chuyên viên phân tích.

**Giá trị mang lại:** Hệ thống chứng minh khả năng phát hiện sớm và ngăn chặn các dấu hiệu tấn công từ trinh sát, dò quét mật khẩu đến xâm nhập qua WinRM.

## 4. QUY TRÌNH VẬN HÀNH & ỨNG CỨU SỰ CỐ

Dự án áp dụng quy trình chuẩn NIST SP 800-61, tập trung vào tính toàn diện:

1. **Phân tích & Phân loại:**

   * Sử dụng SIEM để tương quan log, xác định bản chất sự cố.

   * Loại bỏ cảnh báo giả để tập trung vào các mối đe dọa thực sự.

2. **Ngăn chặn & Cô lập:**

   * Kích hoạt quy trình chặn đứng cuộc tấn công.

   * Với sự hỗ trợ của Mini-SOAR, các lệnh cô lập máy trạm hoặc chặn IP Attacker được thực thi tự động hóa một phần, đảm bảo tốc độ phản ứng tính bằng giây trước khi Ransomware kịp lây lan.

3. **Thu thập & Điều tra số:**

   * Thực hiện trích xuất dữ liệu nóng trên RAM và Disk.

   * Dựng lại dòng thời gian tấn công để truy tìm nguyên nhân gốc rễ.

4. **Khôi phục & Giải mã:**

   * Điểm nhấn kỹ thuật: Phân tích mã độc dựa trên mẫu thu thập được file evtx như script block, security , sysmon để tìm ra thuật toán/khóa giải mã.

   * Mục tiêu: Khôi phục dữ liệu gốc mà không cần thỏa hiệp trả tiền chuộc cho tội phạm.

5. **Củng cố:**

   * Chuyển hóa các IOCs thành luật phát hiện mới để gia cố hệ thống lâu dài.
