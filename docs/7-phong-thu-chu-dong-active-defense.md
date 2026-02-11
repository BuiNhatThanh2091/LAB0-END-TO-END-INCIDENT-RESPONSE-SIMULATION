---
title: 'End-to-End Incident Response Simulation: From Detection to Recovery'
label: 'CHƯƠNG 7: PHÒNG THỦ CHỦ ĐỘNG'
slug: 7-phong-thu-chu-dong-active-defense
description: >-
  Dự án mô phỏng quy trình SOC khép kín: Từ Monitor, Detection đến Digital
  forensics và Recovery kết hợp Mini-SOAR Engine bằng Python theo kiến trúc bảo
  mật 6 lớp giúp tự động hóa toàn bộ quy trình.
visibility: PUBLIC
---
# CHƯƠNG 7: KỊCH BẢN 2 - CHIẾN LƯỢC PHÒNG THỦ CHỦ ĐỘNG VÀ TỐI ƯU HÓA VẬN HÀNH BẰNG SOAR

## PHẦN 1: QUY TRÌNH VẬN HÀNH & TỐI ƯU HÓA CHỈ SỐ SOC

Kịch bản này minh họa sự chuyển dịch chiến lược từ mô hình "Phản ứng thụ động" sang "Phòng thủ chủ động" nhưng vẫn giữ được các giá trị cốt lõi của tư duy phòng thủ. Bằng cách đưa công cụ SOAR kết hợp với tư duy phòng thủ nhằm làm quy trình phòng thủ phân lớp được tự động hóa một phần và hoàn toàn nếu cần thiết.

Mục tiêu cốt lõi của Playbook này là kiểm soát và tối ưu hóa 4 chỉ số đo lường hiệu năng cấp doanh nghiệp:

* **MTTD (Mean Time To Detect):** Đạt mức tối ưu (\< 10 giây) thông qua việc liên tục thu thập Telemetry từ tầng Network : Zeek/Suricata đến Endpoint.

* **MTTI (Mean Time To Investigate):** Giảm từ hàng chục phút xuống 0 phút. SOAR tự động thực hiện tương quan dữ liệu và đối chiếu Threat Intelligence, loại bỏ thao tác tra cứu thủ công của Analyst.

* **MTTR (Mean Time To Respond):** Rút ngắn từ hàng giờ xuống dưới 1 phút thông qua Playbook thực thi tự động.

* **FPR (False Positive Rate):** Hỗ trợ giảm thiểu tình trạng quá tải cảnh báo nhờ cơ chế chấm điểm rủi ro tích lũy, đảm bảo không chặn nhầm người dùng hợp lệ.

### Giai đoạn 1: Sàng lọc & Đưa vào Tầm ngắm

* **Hành vi Kẻ tấn công:** Truy cập vào các Domain/IP độc hại, đồng thời sử dụng Nmap quét bề mặt mạng doanh nghiệp để tìm điểm yếu.

* **Input Layer:**

  * Hệ thống Threat Intelligence đối chiếu IP nguồn 10.10.10.130 và phát hiện lịch sử truy cập bất thường.

  * Suricata : Kích hoạt cảnh báo Signature-based cho hành vi quét cổng.

  * Zeek : Dựa trên thông tin về hoạt động mạng cũng như truy cập vào các port với quy mô lớn.

* **Phản ứng của SOAR:**

  * Ở giai đoạn này, SOAR tuyệt đối không thực hiện chặn cứng nhằm tránh rủi ro kẻ tấn công giả mạo IP hợp lệ gây sập dịch vụ nội bộ .

  * Thay vào đó, Module *Triage* của SOAR đưa IP này vào Dynamic Watchlist. Một mức điểm rủi ro sơ bộ được gán. Trạng thái giám sát chuyển → Cảnh giác cao độ.

### Giai đoạn 2: Xác thực Tương quan & Vi phạm Ngưỡng

* **Hành vi Kẻ tấn công :** Sau khi phát hiện port 5985 của dịch vụ WinRM mở, kẻ tấn công lập tức sử dụng công cụ Hydra để thực hiện tấn công Brute-force hòng chiếm quyền.

* **Cơ chế Phân tích:**

  * SIEM ghi nhận hàng loạt Event ID 4625 từ một IP đang nằm trong diện theo dõi.

  * **Mini Soar** đã thực hiện real time vì thế với cơ chế polling đã nhận được alert và thực hiện liên kết hành vi Brute-force này với IP đang nằm trong *Dynamic Watchlist* từ Giai đoạn 1.

  * Điểm rủi ro bị cộng dồn liên tục theo thời gian thực. Ngay khi điểm số vượt qua ngưỡng dung sai ơ đây điểm số được cho phép là \< 100, hệ thống chính thức dán nhãn đây là "Tấn công có chủ đích".

### Giai đoạn 3: Can thiệp Quyết liệt

* **Hành động của SOAR :** Ngay khoảnh khắc vượt ngưỡng, SOAR trở thành "Cỗ máy thực thi", tự động chạy các hàm ngăn chặn:

  1. **Network Containment**: SOAR giao tiếp API/SSH đẩy luật chặn IP 10.10.10.130 xuống Firewall biên và Host-based Firewall. Cắt đứt mọi nỗ lực kết nối Inbound/Outbound.

  2. **Process Containment** : Thay vì chỉ "Force Logout" người dùng trên bề mặt, SOAR đóng vai trò như một EDR. Nó kết nối sâu vào hệ điều hành, rà quét và Kill Process các tiến trình PowerShell/WinRM độc hại đang chạy ngầm, dập tắt hoàn toàn phiên điều khiển của kẻ tấn công.

### Giai đoạn 4: Hậu quả & Đánh giá

* **Phía Kẻ tấn công:** Nhận thông báo *Connection Refused*. Mất hoàn toàn quyền truy cập vào hạ tầng. Dwell Time bị ép xuống mức 0 trước khi mã độc kịp phát tán.

* **Phía SOC Analyst :** Chuyên viên an ninh nhận được Báo cáo Sự cố tự động qua email chứa đầy đủ: IP tấn công, dòng thời gian sự kiện, tổng điểm rủi ro và các Action đã thực thi. Nhân sự được giải phóng khỏi thao tác tay thủ công, hệ thống được bảo vệ 24/7.

## PHẦN 2: HIỆN THỰC HÓA KỸ THUẬT VÀ PHÂN TÍCH HỆ THỐNG MINI SOAR

Để tự động hóa hoàn toàn quy trình Playbook tại Phần 1, tôi đã trực tiếp tham gia thiết kế và phát triển một Mini-SOAR Engine bằng ngôn ngữ Python.

Hệ thống này không phải là một đoạn script "chạy thẳng từ trên xuống" . Nó được thiết kế theo tư duy Kiến trúc Phân lớp, hoạt động theo vòng lặp thời gian . Để một IP bị chặn, luồng dữ liệu log phải đi qua 6 "màng lọc" logic khắt khe nhằm đảm bảo tính chính xác tuyệt đối và an toàn cho hệ thống doanh nghiệp.

Dưới đây là kiến trúc hệ thống và tư duy đằng sau từng dòng code:

### 1. Tầng Thu thập & Bền vững

Ta sẽ thực hiện gọi các hàm tìm kiếm, kiểm tra trên 2 file <a target="_blank" href="https://github.com/BuiNhatThanh2091/LAB0-END-TO-END-INCIDENT-RESPONSE-SIMULATION/blob/main/scripts/response_auto/ingestion.py">ingestion.py</a> & <a target="_blank" href="https://github.com/BuiNhatThanh2091/LAB0-END-TO-END-INCIDENT-RESPONSE-SIMULATION/blob/main/scripts/response_auto/checkpoint.py">checkpoint.py</a> để lưu lại trạng thái , lúc này khi mà hệ thống đọc được logs thì sẽ lưu lại mốc thời gian dẫn đến khi thực hiện gọi đến SPL CLI tiếp theo thì Soar chỉ cần kéo các logs sau mốc thời gian và cũng đảm bảo việc không mất dữ liệu và tối ưu hóa băng thông mạng.

### 2. Tầng Tương quan & Khử nhiễu

Tránh việc xử lý các logs trùng lặp, tôi xây dựng thuật toán Deduplication ở file [correlation.py](https://github.com/BuiNhatThanh2091/LAB0-END-TO-END-INCIDENT-RESPONSE-SIMULATION/blob/main/scripts/response_auto/correlation.py). Hệ thống tạo ra một Hash Key cho mỗi sự kiện gồm: (IP Nguồn + Cổng Đích + Loại Sự Kiện). Mọi sự kiện có chung khóa này, nếu xảy ra trong một Time window - 5 giây, sẽ bị gộp chung thành 1 sự kiện duy nhất. Logic này giúp SOAR giữ sự nhận diện liên tục tránh bỏ sót các thông tin, chấm điểm chính xác và chống nhiễu hiệu quả.

### 3. Tầng Đánh giá Rủi ro & Hạ nhiệt

Việc làm sao phân biết giữa một nhân viên IT gõ sai mật khẩu với một cuộc tấn công Brute Force thì ở đây ta thực hiện áp dung bộ quy tắc trong file [scoring.py](https://github.com/BuiNhatThanh2091/LAB0-END-TO-END-INCIDENT-RESPONSE-SIMULATION/blob/main/scripts/response_auto/scoring.py) là hành động các nguy hiểm điểm cộng càng cao. Mỗi lỗi hay câu lệnh được phát hiện từ Chương 5 đều tạo thành các rules để hiện thực hóa cách tính điểm. Ngoài ra làm sao để tránh được False Positive thì ta sẽ dựa trên chu kỳ nếu một địa chỉ Ip nằm trong Watchlist không phát sinh thêm những hành vi được quy định là đáng ngờ thì hệ thống sẽ gọi đến hàm apply\_decay() để trừ bớt điểm của IP đó. Nhờ thế hệ thống tha thứ cho những lỗi thao tác vô tình của người dùng hợp lệ sau một khoảng thời gian.

### 4. Tầng Ra Quyết Định

Việc làm sao xử lý rủi ro khi hacker giả mạo IP của các tài sản quan trọng như Domain Controller hay máy Giám đốc để tránh tình trạng hệ thống tự đánh sập mạng nhà thì ở đây ta thực hiện cơ chế sàng lọc trong file [`decision.py`](https://github.com/BuiNhatThanh2091/LAB0-END-TO-END-INCIDENT-RESPONSE-SIMULATION/blob/main/scripts/response_auto/decision.py). Module này hoạt động như một lớp bảo vệ cuối cùng, luôn đối chiếu IP vi phạm với danh sách WHITELIST\_IPS trước khi ra quyết định. Ngoài ra đối với các IP đặc biệt này thì ngưỡng chặn sẽ được đẩy lên mức rất cao là trên 250 điểm hoặc chuyển sang chế độ chỉ gửi cảnh báo chờ người quản trị xác thực chứ không thực thi khóa mạng ngay lập tức. Nhờ thế hệ thống kiểm soát được quyền "sinh sát" của tự động hóa, đảm bảo an toàn cho hạ tầng cốt lõi.

### 5. Tầng Phản Ứng & Can Thiệp Sâu (Active Response & EDR Capabilities)

* Việc đơn thuần ngắt kết nối mạng tại Firewall là chưa đủ để dập tắt hoàn toàn mối nguy, bởi lẽ nếu phiên WinRM đã được thiết lập thì mã độc vẫn đang thường trú trên RAM của máy trạm và các lệnh Force Logout user thường vô dụng với System Process. Để giải quyết triệt để, ta thực hiện cơ chế phản ứng chiều sâu được hiện thực hóa trong hai module [`response.py`](https://github.com/BuiNhatThanh2091/LAB0-END-TO-END-INCIDENT-RESPONSE-SIMULATION/blob/main/scripts/response_auto/response.py) và `process_`[`containment.py`](https://github.com/BuiNhatThanh2091/LAB0-END-TO-END-INCIDENT-RESPONSE-SIMULATION/blob/main/scripts/response_auto/process_containment.py).

  Tại đây, hệ thống không chỉ chặn IP ở cấp độ mạng thông qua iptables/Windows Firewall mà còn hoạt động như một XDR thu nhỏ ở cấp độ máy trạm: nó chủ động kết nối SSH, quét danh sách tiến trình qua WMI/Tasklist và kích hoạt hàm identify\_malicious() để truy tìm và tiêu diệt ngay lập tức các chuỗi lệnh độc hại như là: powershell -enc. Đặc biệt, để đảm bảo an toàn vận hành và tránh việc SOAR kill nhầm gây lỗi màn hình xanh cho máy chủ, ta áp dụng cơ chế Safety Net với danh sách PROTECTED\_PROCESSES (như svchost.exe, lsass.exe) để quy định các tiến trình hệ thống cốt lõi là bất khả xâm phạm.

Sau khi thực hiện xong các việc BLOCK đối với Ip được cho là nguy hiểm , Kill đối với các dịch vụ được sử dụng bởi các Ip đó thì ta cũng sẽ phải đặt lại các chốt chặn an toàn bằng các sẽ gửi Email đến người quản trị hệ thống tránh việc BLOCK nhầm các Ip được coi là an toàn nhưng không nằm trong whitelist

<Image src="https://cdn.hashnode.com/res/hashnode/image/upload/v1770798227448/19438e79-2548-4d44-a4ef-06ecba51eda0.png" align="center" fullwidth="false" />
