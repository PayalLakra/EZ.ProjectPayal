from flask_mail import Message
from . import mail

def send_verification_email(user):
    token = user.get_reset_token()
    msg = Message('Account Verification', 
                  sender='noreply@demo.com', 
                  recipients=[user.email])
    msg.body = f'''To verify your account, visit the following link:
{url_for('verify_email', token=token, _external=True)}

    mail.send(msg)
