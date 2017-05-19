import hmac
import hashlib
from datetime import datetime

# GET /book HTTP/1.1
# X-Credentials: <public_key>.<timestamp>.<algorithm>
# X-Signature: HMAC-SHA256(<method>.<path>.<timestamp>)
# Timestamp: 2017-05-14T17:54:16Z
# Algorithm: HMAC-SHA256

ALGORITHM = 'HMAC-SHA256'
TIMESTAMP_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


def format_datetime_iso(d):
    return d.strftime(TIMESTAMP_FORMAT)


def parse_datetime_iso(d):
    return datetime.strptime(d, TIMESTAMP_FORMAT)


def get_current_timestamp():
    return format_datetime_iso(datetime.utcnow())


def _utf8(s):
    return s.encode('utf-8')


def sign(public_key, secret_key, method='GET', path='/', timestamp=None):
    ts = format_datetime_iso(timestamp or datetime.utcnow())

    signature_str = "{}.{}.{}".format(method.upper(), path, ts)
    credentials = "{}.{}.{}".format(public_key, ts, ALGORITHM)

    digest_maker = hmac.new(_utf8(secret_key), digestmod=hashlib.sha256)
    digest_maker.update(_utf8(signature_str))

    return (digest_maker.hexdigest(), credentials)
