import argparse
from api.custom_auth import sign


def main():
    parser = argparse.ArgumentParser(description='Sign Custom Auth')

    parser.add_argument(
        'public_key', metavar='PK', type=str, help='Public Key')
    parser.add_argument(
        'secret_key', metavar='SK', type=str, help='Secret Key')
    parser.add_argument('method', metavar='M', type=str, help='HTTP Method')
    parser.add_argument('path', metavar='P', type=str, help='Path')

    args = parser.parse_args()
    signature, credentials = sign(
        args.public_key, args.secret_key, args.method, args.path)
    print('Credentials: "{}"'.format(credentials))
    print('Signature: "{}"'.format(signature))


if __name__ == '__main__':
    main()
