import boto3
import logging
from flask import jsonify
from botocore.exceptions import NoCredentialsError, PartialCredentialsError

# AWS SES Configuration
AWS_ACCESS_KEY = "AKIAWWX4V2ESN5YS2DEN"
AWS_SECRET_KEY = "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"
AWS_REGION = "us-east-1"
SENDER = "donotreply@century.ae"
RECIPIENT = "manavajmera2003@gmail.com"
SUBJECT = "Domain Takedown Request"
BODY_TEXT_TEMPLATE = "A takedown request has been made for the domain: {}\n"
BODY_HTML_TEMPLATE = """
<html>
<head></head>
<body>
  <h1>Domain Takedown Request</h1>
  <p>A takedown request has been made for the domain: <b>{}</b>.</p>
</body>
</html>
"""
CHARSET = "UTF-8"

def send_email_takedown(domain):
    body_text = BODY_TEXT_TEMPLATE.format(domain)
    body_html = BODY_HTML_TEMPLATE.format(domain)

    try:
        # Initialize the SES client
        ses_client = boto3.client(
            'ses',
            region_name=AWS_REGION,
            aws_access_key_id=AWS_ACCESS_KEY,
            aws_secret_access_key=AWS_SECRET_KEY
        )

        # Send the email
        response = ses_client.send_email(
            Source=SENDER,
            Destination={
                'ToAddresses': [RECIPIENT]
            },
            Message={
                'Subject': {
                    'Data': SUBJECT,
                    'Charset': CHARSET
                },
                'Body': {
                    'Text': {
                        'Data': body_text,
                        'Charset': CHARSET
                    },
                    'Html': {
                        'Data': body_html,
                        'Charset': CHARSET
                    }
                }
            }
        )

        return {"message": f"Email sent! Message ID: {response['MessageId']}"}

    except NoCredentialsError:
        logging.error("NoCredentialsError: AWS credentials not available.")
        return {"message": "Credentials not available. Please check your AWS access and secret keys."}, 500
    except PartialCredentialsError:
        logging.error("PartialCredentialsError: Incomplete AWS credentials provided.")
        return {"message": "Incomplete credentials provided."}, 500
    except Exception as e:
        logging.error(f"Error sending email: {str(e)}")
        return {"message": f"Error sending email: {str(e)}"}, 500