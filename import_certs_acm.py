import base64
import datetime
import json
import logging
import os
import re
import sys

from kubernetes import client, config
from cryptography import x509
from cryptography.hazmat.primitives import serialization
import boto3
from botocore.exceptions import ClientError


config.load_incluster_config()
k8s_core_v1 = client.CoreV1Api()

# Configuration
NAMESPACE = os.environ.get('NAMESPACE', 'default')
SECRET_NAME = os.environ.get('SECRET_NAME', 'your-certificate-secret')
AWS_REGION = os.environ.get('AWS_REGION', 'us-west-2')
DOMAIN_NAME = os.environ.get('DOMAIN_NAME', 'example.com')
DAYS_BEFORE_EXPIRY = os.environ.get('DAYS_BEFORE_EXPIRY', 30)
FORCE_IMPORT = os.environ.get('FORCE_IMPORT', 'false').lower() in ('true', 'yes', '1')
DEFAULT_TAGS = [
    {
        'Key': 'owner',
        'Value': 'cert-manager'
    },
    {
        'Key': 'k8s-namespace',
        'Value': NAMESPACE
    },
    {
        'Key': 'team-name',
        'Value': 'devops'
    },
    {
        'Key': 'team-owner-name',
        'Value': 'Greg Whorley'
    }
]
log_level_str = os.environ.get("LOG_LEVEL", "INFO").upper()
LOG_LEVEL = getattr(logging, log_level_str, logging.INFO)


class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Include any exception information if present
        if record.exc_info:
            log_record["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]),
                "traceback": self.formatException(record.exc_info)
            }

        # Include any extra fields from the record
        for key, value in record.__dict__.items():
            if key not in ["args", "asctime", "created", "exc_info", "exc_text",
                           "filename", "funcName", "id", "levelname", "levelno",
                           "lineno", "module", "msecs", "message", "msg", "name",
                           "pathname", "process", "processName", "relativeCreated",
                           "stack_info", "thread", "threadName"]:
                log_record[key] = value

        return json.dumps(log_record)


def setup_logger():
    logger = logging.getLogger()
    logger.setLevel(LOG_LEVEL)

    # Create handler for stdout
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)

    return logger


def extract_cert_chain(cert_data):
    """
    Extract certificates from the chain:
    - First extract the issued certificate (first in the chain)
    - Then extract the remaining certificates in the chain (excluding the first one)

    Returns a tuple containing (issued_certificate, certificate_chain)
    """
    pattern = r'(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)'
    matches = re.findall(pattern, cert_data, re.DOTALL)

    if not matches:
        return (cert_data, "")

    issued_cert = matches[0]
    if len(matches) > 1:
        cert_chain = '\n'.join(matches[1:])
    else:
        cert_chain = ""

    return issued_cert, cert_chain


def get_certificate_expiration(cert_data):
    """Parse certificate and return expiration date"""
    cert = x509.load_pem_x509_certificate(cert_data.encode('utf-8'))
    return cert.not_valid_after_utc


def should_import_certificate(expiration_date, days_before_expiry=DAYS_BEFORE_EXPIRY):
    """Determine if certificate should be imported based on expiration"""
    if FORCE_IMPORT:
        logger.info("Force import enabled - bypassing expiration check")
        return True
    logger.info("Calculating remaining days before expiration.")
    # Convert to timezone-naive datetime if needed
    if expiration_date.tzinfo is not None:
        logger.info(f"Timezone data found in expiration date. Converting to UTC and removing tzinfo.")
        # Make expiration_date timezone-naive by converting to UTC then removing tzinfo
        expiration_date = expiration_date.astimezone(datetime.timezone.utc).replace(tzinfo=None)
    logger.info(f"Was given date: {expiration_date}")
    # Use the modern approach for getting UTC time
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    logger.info(f"Current date in UTC: {now}")
    days_until_expiry = (expiration_date - now).days
    logger.info(f"Certificate expires in {days_until_expiry} days (on {expiration_date})")
    return days_until_expiry <= days_before_expiry


def find_existing_certificate(acm_client, domain_name):
    """
    Find existing ACM certificate for a given domain name.
    Returns a tuple (arn, expiration_date) if found, otherwise (None, None).
    """
    try:
        logger.info("Listing certificates")
        paginator = acm_client.get_paginator('list_certificates')
        for page in paginator.paginate(Includes={'keyTypes': ['RSA_2048', 'RSA_4096']}):
            for cert in page['CertificateSummaryList']:
                # Retrieve full certificate details
                cert_details = acm_client.describe_certificate(
                    CertificateArn=cert['CertificateArn']
                )
                logger.debug(f"Full cert details:\n{cert_details}")
                domains = cert_details['Certificate'].get('SubjectAlternativeNames', [])
                logger.debug(f"Found domains in cert:\n{domains}")
                if any(domain_name in domain for domain in domains):
                    expiration_date = cert_details['Certificate'].get('NotAfter')
                    if expiration_date:
                        logger.info(f"Found matching certificate with ARN {cert['CertificateArn']} expiring on {expiration_date}")
                        return cert['CertificateArn'], expiration_date
                    else:
                        logger.warning(f"No expiration date found for certificate {cert['CertificateArn']}")
                        return cert['CertificateArn'], None
        logger.info("No existing cert found. Returning null.")
        return None, None
    except ClientError as e:
        logger.warning(f"Error while finding existing certificate:\n{e}")
        return None, None


def main():
    logger.info("Starting up")
    try:
        # Initialize AWS ACM client
        acm_client = boto3.client('acm', region_name=AWS_REGION)
        logger.info(f"Fetching secret {SECRET_NAME}")
        secret = k8s_core_v1.read_namespaced_secret(SECRET_NAME, NAMESPACE)

        logger.info("Decoding cert and private key data.")
        cert_data = base64.b64decode(secret.data['tls.crt']).decode('utf-8')
        key_data = base64.b64decode(secret.data['tls.key']).decode('utf-8')

        logger.info("Extracting certificate chain into tuple.")
        first_cert, cert_chain = extract_cert_chain(cert_data)
        logger.info("Successfully extracted the certs.")

        logger.info("Writing cert/key data to files for potential import to ACM.")
        with open('/tmp/tls.crt', 'w') as cert_file:
            cert_file.write(first_cert)
        with open('/tmp/tls.key', 'w') as key_file:
            key_file.write(key_data)
        import_params = {
            'Certificate': open('/tmp/tls.crt', 'rb').read(),
            'PrivateKey': open('/tmp/tls.key', 'rb').read(),
            'Tags': DEFAULT_TAGS
        }
        if cert_chain:
            logger.info("Writing cert chain to separate file for importing.")
            with open('/tmp/certificate_chain.pem', 'w') as chain_file:
                chain_file.write(cert_chain)
            import_params['CertificateChain'] = open('/tmp/certificate_chain.pem', 'rb').read()
        if FORCE_IMPORT:
            import_params.pop('Tags')  # Remove the tags when forcing a re-import of certs

        logger.info(f"Finding existing certificate for {DOMAIN_NAME}")
        existing_cert_arn, acm_expiration_date = find_existing_certificate(acm_client, DOMAIN_NAME)

        if existing_cert_arn:
            logger.info("Certificate exists in ACM, checking if it needs to be updated")
            # Only check ACM expiration if we have a date
            if acm_expiration_date:
                # ACM returns datetime objects directly
                if should_import_certificate(acm_expiration_date):
                    logger.info("ACM certificate is about to expire and should be updated.")
                    import_params['CertificateArn'] = existing_cert_arn
                    response = acm_client.import_certificate(**import_params)
                    logger.info(f"Replaced existing certificate. ARN: {existing_cert_arn}")
                    logger.debug(response)
                else:
                    logger.info(f"ACM certificate is not close to expiry. Expiration: {acm_expiration_date}")
            else:
                # If we couldn't get expiration date from ACM, we should update the certificate
                logger.info("Could not determine ACM certificate expiration date, updating to be safe.")
                import_params['CertificateArn'] = existing_cert_arn
                response = acm_client.import_certificate(**import_params)
                logger.info(f"Replaced existing certificate due to missing expiration data. ARN: {existing_cert_arn}")
                logger.debug(response)
        else:
            logger.info("No matching certificate found in ACM. Importing new certificate.")
            response = acm_client.import_certificate(**import_params)
            logger.info(f"Imported new certificate. ARN: {response['CertificateArn']}")
    except Exception as e:
        logger.error(f"Error processing certificate:\n{e}")
        exit(1)


if __name__ == "__main__":
    logger = setup_logger()
    main()
