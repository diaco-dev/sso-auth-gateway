import json
import logging
import requests
from app.core.celery import celery_app
from app.core.config import settings
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
import asyncio
logger = logging.getLogger(__name__)

# -----------------------
# Email Config
# -----------------------
conf = ConnectionConfig(
    MAIL_USERNAME=settings.MAIL_USERNAME,
    MAIL_PASSWORD=settings.MAIL_PASSWORD,
    MAIL_FROM=settings.MAIL_FROM,
    MAIL_PORT=settings.MAIL_PORT,
    MAIL_SERVER=settings.MAIL_SERVER,
    MAIL_STARTTLS=settings.MAIL_STARTTLS,
    MAIL_SSL_TLS=settings.MAIL_SSL_TLS,
    USE_CREDENTIALS=settings.USE_CREDENTIALS,
    VALIDATE_CERTS=False
)


# -----------------------
# Logger
# -----------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# -----------------------
# Email Task
# -----------------------
@celery_app.task(name="app.core.tasks.send_verification_email")
def send_verification_email(email: str, code: str):
    """
    Send verification email to user asynchronously using FastMail.
    Logs every step for debugging.
    """
    logger.info(f"Preparing email to {email}")

    subject = "کد تأیید ثبت‌نام"
    message = f"کد تأیید شما: {code}"

    message_obj = MessageSchema(
        subject=subject,
        recipients=[email],
        body=message,
        subtype="plain"
    )

    fm = FastMail(conf)

    try:
        logger.info(f"Connecting to SMTP server {settings.MAIL_SERVER}:{settings.MAIL_PORT}")
        asyncio.run(fm.send_message(message_obj))
        logger.info(f"Email successfully sent to {email}")
    except Exception as e:
        logger.error(f"Failed to send email to {email}: {e}", exc_info=True)



def send_sms(receptor: str, variables: dict, pattern_code: str):
    url = "https://api2.ippanel.com/api/v1/sms/pattern/normal/send"
    payload = json.dumps({
        "code": pattern_code,
        "sender": settings.farazsms_sender,
        "recipient": receptor,
        "variable": variables
    })
    headers = {
        'apikey': settings.farazsms_api_key,
        'Content-Type': 'application/json'
    }

    logger.info(f"Sending SMS to {receptor} with payload: {payload}")
    try:
        response = requests.post(url, headers=headers, data=payload)
        if response.status_code == 200:
            logger.info(f"SMS sent to {receptor}")
        else:
            logger.error(f"Error sending SMS {response.status_code}: {response.text}")
        return response
    except Exception as e:
        logger.error(f"Exception in send_sms: {e}", exc_info=True)

@celery_app.task(name='app.core.tasks.send_verification_sms')
def send_verification_sms(mobile: str, code: str):
    logger.info(f"Starting to send SMS to {mobile} with code {code}")
    try:
        variables = {
            "verification-code": str(code)
        }
        send_sms(mobile, variables, 'x7a68g929i09924')
    except Exception as e:
        logger.error(f"Error in send_verification_sms: {e}", exc_info=True)
