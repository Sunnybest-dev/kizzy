import smtplib
from email.mime.text import MIMEText

def send_alert(threat, ip):
    sender = "chiomymusic@gmail.com"
    password = "vkxiddrwgtmalzzn"
    receiver = "sunnybestcontact@gmail.com"

    msg = MIMEText(f"{threat} detected from {ip}")
    msg["Subject"] = "🚨 Cybersecurity Alert"
    msg["From"] = sender
    msg["To"] = receiver

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(sender, password)
        server.send_message(msg)