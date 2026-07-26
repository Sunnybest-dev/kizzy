import smtplib
import os
from email.mime.text import MIMEText

def send_alert(threat, ip):
    sender = os.environ.get("ALERT_SENDER")
    password = os.environ.get("ALERT_PASSWORD")
    receiver = os.environ.get("ALERT_RECEIVER")

    if not all([sender, password, receiver]):
        print(f"[ALERT] {threat} from {ip} (email not configured)")
        return

    msg = MIMEText(f"{threat} detected from {ip}")
    msg["Subject"] = "🚨 Cybersecurity Alert"
    msg["From"] = sender
    msg["To"] = receiver

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender, password)
            server.send_message(msg)
    except Exception as e:
        print(f"[ALERT ERROR] {e}")
