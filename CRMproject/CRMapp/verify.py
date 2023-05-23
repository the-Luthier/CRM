import os
from twilio.rest import Client
from twilio.base.exceptions import TwilioRestException
from dotenv import load_dotenv

load_dotenv()

client = Client(os.getenv("TWILIO_ACCOUNT_SID"), os.getenv("TWILIO_AUTH_TOKEN"))
verify = client.verify.v2.services(os.environ["TWILIO_VERIFY_SERVICE_SID"])



def send(phone):
    verify.verifications.create(to=phone, channel='sms')


def check(phone, code):
    try:
        result = verify.verification_checks.create(to=phone, code=code)
    except TwilioRestException:
        print('no')
        return False
    return result.status == 'approved'



def send_mail(email):
    verify.verifications.create(to=email, channel=email)



def check_mail(email,code):
    try:
        result = verify.verification_checks.create(to=email, code=code)
    except:
        email.is_valid = False
        print('no')
        return False
    return result.status == 'approved'


