---
title: 'End-to-End Incident Response Simulation: From Detection to Recovery'
label: 'CHƯƠNG 8.3: MÔ HÌNH DIAMOND MODEL'
slug: 83-mo-hinh-kim-cuong-diamond-model
description: >-
  Dự án mô phỏng quy trình SOC khép kín: Từ Monitor, Detection đến Digital
  forensics và Recovery kết hợp Mini-SOAR Engine bằng Python theo kiến trúc bảo
  mật 6 lớp giúp tự động hóa toàn bộ quy trình.
visibility: PUBLIC
---
# CHƯƠNG 8.3 : MÔ HÌNH DIAMOND MODEL

### Phân tích Intrusion Analysis qua Diamond Model

**Nội dung:** Mô hình này giúp ta xác định rõ mối quan hệ giữa 4 yếu tố cốt lõi của cuộc tấn công.

* **Adversary :**

  * **Nguồn gốc:** External Attacker .

  * **IP:** 10.10.10.130.

  * **Động cơ:** Tài chính, Data Exfiltration.

  **Infrastructure :**

  * **Attacker:** Kali Linux chạy trên VMware.

  * **Giao thức C2:** WinRM Port 5985/TCP.

  * **Công cụ hỗ trợ:** MailHog , Python HTTP Server .

  **Capability :**

  * **Tool tấn công**: Hydra , Evil-WinRM .

  * **Malware**: Custom PowerShell Script.

* **Victim :**

  * **Mục tiêu:** Máy trạm Windows 10 Enterprise.

  * **User bị ảnh hưởng:** thanh .

  * **Tài sản bị xâm phạm:** Các file tài liệu quan trọng → .txt, .docx.
