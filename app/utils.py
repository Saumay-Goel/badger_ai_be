import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from jinja2 import Environment, FileSystemLoader
import random
import string
import os
from app.core.config import settings

template_dir = os.path.join(os.path.dirname(__file__), 'email_templates')
env = Environment(loader=FileSystemLoader(template_dir))


def generate_otp(length=6):
    return ''.join(random.choices(string.digits, k=length))


def send_email(to_email: str, subject: str, template_name: str, context: dict):
    print("send mail function started")
    try:
        template = env.get_template(template_name)
        html_content = template.render(context)

        msg = MIMEMultipart()
        msg['From'] = settings.SMTP_USER
        msg['To'] = to_email
        msg['Subject'] = subject

        msg.attach(MIMEText(html_content, 'html'))

        server = smtplib.SMTP(settings.SMTP_SERVER, settings.SMTP_PORT)
        server.starttls()
        server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
        server.sendmail(settings.SMTP_USER, to_email, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False


def send_otp_email(to_email: str, otp: str):
    return send_email(
        to_email=to_email,
        subject="Verify your Badger Agent Account",
        template_name="verification.html",
        context={"otp": otp}
    )


def send_welcome_email(to_email: str, username: str):
    return send_email(
        to_email=to_email,
        subject="Welcome to Badger Agent! 🚀",
        template_name="welcome.html",
        context={"username": username}
    )
