---
title: 'End-to-End Incident Response Simulation: From Detection to Recovery'
label: 'CHƯƠNG 2: CẤU TRÚC & KỊCH BẢN '
slug: cau-truc-chi-tiet-bai-lab
description: >-
  Dự án mô phỏng quy trình SOC khép kín: Từ Monitor, Detection đến Digital
  forensics và Recovery kết hợp Mini-SOAR Engine bằng Python theo kiến trúc bảo
  mật 6 lớp giúp tự động hóa toàn bộ quy trình.
visibility: PUBLIC
---
# CHƯƠNG 2. CẤU TRÚC & KỊCH BẢN

## 1. MÔ HÌNH ĐE DỌA & KỊCH BẢN MÔ PHỎNG

**Bối cảnh chiến lược:**

Dự án xây dựng môi trường giả lập tái hiện kiến trúc mạng của một tổ chức Tài chính. Hệ thống đối mặt với các tác nhân đe dọa bên ngoài sử dụng kỹ thuật tấn công APT nhằm mục đích tống tiền và đánh cắp dữ liệu.

**Vector tấn công chủ đạo:**

* **Identity Compromise:** Tấn công vào yếu tố con người qua Spear Phishing.

* **Living-off-the-Land :** Lạm dụng giao thức quản trị hợp pháp WinRM - Port 5985 để né tránh các giải pháp bảo mật truyền thống.

### So sánh Hiệu quả Vận hành

#### Kịch bản A: Quy trình Phản ứng Thụ động

*Trạng thái: Chưa tích hợp Tự động hóa.*

* **Diễn biến:** Attacker dò quét → Chiếm quyền → Mã hóa dữ liệu.

* **Điểm yếu vận hành:**

  * **Visibility Gap:** Cảnh báo từ SIEM bị trôi trong hàng nghìn log nhiễu.

  * **High MTTR:** Thời gian từ lúc phát hiện đến khi cô lập máy trạm kéo dài hàng giờ do thao tác thủ công.

  * **Hậu quả:** Dữ liệu bị mã hóa, vi phạm tính toàn vẹn hệ thống.

#### Kịch bản B: Phòng thủ Chủ động với SOAR

*Trạng thái: Tích hợp Module Mini-SOAR.*

* **Cơ chế hoạt động:**

  1. **Early Detection:** Các cảm biến mạng như Suricata/Zeek phát hiện dấu hiệu bất thường từ giai đoạn trinh sát .

  2. **Automated Triage:** Module SOAR tự động chấm điểm rủi ro dựa trên hành vi và tương quan log.

  3. **Instant Containment:** Ngay khi điểm rủi ro vượt ngưỡng , SOAR tự động thực thi chính sách Zero Trust:

     * Ngắt phiên kết nối WinRM/SSH đáng ngờ.

     * Đẩy luật chặn IP xuống Firewall biên.

* **Kết quả:** Chuỗi tấn công bị bẻ gãy ngay lập tức. MTTR giảm xuống \< 1 phút.

## 2. MỤC TIÊU KỸ THUẬT & CHIẾN LƯỢC

1. **Làm chủ kiến trúc:** Thiết kế và vận hành hệ thống giám sát phân lớp , đảm bảo khả năng hiển thị toàn trình từ Network đến Endpoint.

2. **Kỹ nghệ phát hiện:** Chuyển đổi các TTPs (Tactics, Techniques, Procedures) của Hacker thành các luật phát hiện chuẩn xác trên SIEM, giảm thiểu False Positive.

3. **Hiện thực hóa tự động hóa:** Chứng minh vai trò của SOAR như một phần không thể tách rời giúp đội ngũ SOC giảm tải các tác vụ lặp lại để tập trung vào phân tích sâu.

4. **Khả năng phục hồi:** Xây dựng quy trình DFIR bài bản để khôi phục tài sản số mà không thỏa hiệp với tội phạm mạng.

## 3. THIẾT KẾ HẠ TẦNG & CÔNG NGHỆ

Hệ thống được quy hoạch thành các vùng mạng chức năng để đảm bảo nguyên tắc phân tách và kiểm soát truy cập.

<Image src="https://cdn.hashnode.com/res/hashnode/image/upload/v1770736499208/7afc179c-04e0-4b53-b57b-b714cf5ae9e6.png" alt="" align="center" fullwidth="true" />

### A. Defensive Zone

**1. High-Value Assets :**

* **Endpoint:** Windows 10 Enterprise .

* **Security Posture:** Được cấu hình có chủ đích các lỗ hổng như mở port WinRM public để kiểm thử năng lực phát hiện.

* **Telemetry Agents:**

  * **Sysmon:** Cấu hình theo chuẩn SwiftOnSecurity để giám sát sâu: Process Injection, Network Connections, File Creation.

  * **Winlogbeat:** Vận chuyển log thời gian thực, đảm bảo tính toàn vẹn của bằng chứng số.

**2. Security Operations Center :**

* **Nền tảng:** Ubuntu Server.

* **Stack Công nghệ:**

  * **SIEM :** Trung tâm phân tích, tương quan sự kiện và Dashboard hiển thị trạng thái an ninh.

  * **Network Sensors:** Hệ thống phát hiện xâm nhập (IDS) kết hợp phân tích Metadata mạng (NSM) để giám sát luồng traffic đi qua.

  * **Vector:** Pipeline xử lý log hiệu năng cao, đóng vai trò đệm và chuẩn hóa dữ liệu trước khi nạp vào SIEM.

  * **Mini-SOAR:** Một thành phần bổ trợ chiến lược. Một engine Python tùy biến chạy ngầm, liên tục đánh giá rủi ro và thực thi phản ứng tự động.

### B. Adversary Simulation Zone

**3. Threat Actor Infrastructure :**

* **Platform:** Kali Linux .

* **Offensive Toolset :**

  * **Initial Access:** MailHog & Python HTTP .

  * **Reconnaissance:** Nmap .

  * **Credential Access:** Hydra.

  * **C2 Framework:** Evil-WinRM .

  * **Payload:** Custom PowerShell Script .
