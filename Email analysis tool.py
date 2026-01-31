import re
import email
from email import policy
from email.parser import BytesParser

def analyze_email_header(file_path):
    print(f"[*] Đang phân tích file: {file_path}...\n")
    
    try:
        with open(file_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)
    except FileNotFoundError:
        print(f"[!] Lỗi: Không tìm thấy file {file_path}")
        return

    alerts = []
    score = 0

    # Lấy thông tin cơ bản
    subject = msg.get('Subject', '')
    from_header = msg.get('From', '')
    return_path = msg.get('Return-Path', '')
    auth_results = msg.get('Authentication-Results', '')
    
    # ---------------------------------------------------------
    # DETECTION LOGIC (Logic phát hiện)
    # ---------------------------------------------------------

    # 1. Kiểm tra Authentication (SPF/DKIM/DMARC)
    # Vector: Email Spoofing
    if "spf=fail" in auth_results.lower() or "dkim=fail" in auth_results.lower() or "dmarc=fail" in auth_results.lower():
        alerts.append("[CRITICAL] Phát hiện thất bại trong xác thực Email (SPF/DKIM/DMARC Fail).")
        score += 5

    # 2. Kiểm tra Mismatched Sender (Giả mạo người gửi)
    # Vector: Social Engineering
    # Trích xuất email từ trường From và Return-Path để so sánh
    email_pattern = r'<([^>]+)>'
    from_match = re.search(email_pattern, from_header)
    return_match = re.search(email_pattern, return_path)
    
    if from_match and return_match:
        from_email = from_match.group(1)
        return_email = return_match.group(1)
        # So sánh domain
        if from_email.split('@')[-1] != return_email.split('@')[-1]:
            alerts.append(f"[HIGH] Địa chỉ người gửi không khớp (From: {from_email} != Return-Path: {return_email})")
            score += 3

    # 3. Kiểm tra các từ khóa khẩn cấp trong Subject
    # Vector: Phishing (Tạo áp lực tâm lý)
    urgency_keywords = ['urgent', 'immediately', 'action required', 'account suspended', 'verify', 'expiry']
    if any(keyword in subject.lower() for keyword in urgency_keywords):
        alerts.append(f"[MEDIUM] Tiêu đề chứa từ khóa tạo áp lực/khẩn cấp: '{subject}'")
        score += 1

    # 4. Kiểm tra tệp đính kèm nguy hiểm
    # Vector: Malicious Attachments
    # Script quét qua các phần (parts) của email để tìm file đính kèm
    for part in msg.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        if part.get('Content-Disposition') is None:
            continue
            
        filename = part.get_filename()
        if filename:
            suspicious_exts = ['.exe', '.scr', '.vbs', '.js', '.bat', '.cmd', '.iso']
            if any(filename.lower().endswith(ext) for ext in suspicious_exts):
                alerts.append(f"[CRITICAL] Phát hiện tệp đính kèm có đuôi nguy hiểm: {filename}")
                score += 5

    # ---------------------------------------------------------
    # KẾT QUẢ BÁO CÁO
    # ---------------------------------------------------------
    print("=== KẾT QUẢ PHÁT HIỆN MỐI ĐE DỌA ===")
    print(f"Tiêu đề: {subject}")
    print(f"Người gửi: {from_header}")
    print("-" * 40)
    
    if alerts:
        print(f"PHÁT HIỆN: {len(alerts)} dấu hiệu đáng ngờ.")
        for alert in alerts:
            print(alert)
    else:
        print("Không phát hiện dấu hiệu bất thường rõ ràng.")

    print("-" * 40)
    if score >= 5:
        print("KẾT LUẬN: EMAIL NGUY HIỂM CAO - KHUYẾN NGHỊ CHẶN/CÁCH LY")
    elif score >= 1:
        print("KẾT LUẬN: EMAIL ĐÁNG NGỜ - CẦN KIỂM TRA THÊM")
    else:
        print("KẾT LUẬN: EMAIL SẠCH")

# Chạy script với file mẫu
if __name__ == "__main__":
    analyze_email_header("suspicious_email.txt")