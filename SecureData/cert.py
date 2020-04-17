from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from OpenSSL import crypto
import random
from base64 import b64encode, b64decode


def generate_cert(days: int = 365, size: int = 2048, serial_number: int = random.getrandbits(64),
                  public_key: str = './public.crt', private_key: str = './private.key'):
    """
    Generate an SSL certificate and output a public.crt and a private.key.

    :param days:
    :param size:
    :param serial_number:
    :param public_key:
    :param private_key:

    :return:
    """

    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, size)
    country_name = input('Country Name (2 letter code) [XX]: ')
    state_or_province = input('State or Province Name (full name) [Default State/Province]: ')
    locality_name = input('Locality Name (eg, city) [Default City]: ')
    organization_name = input('Organization Name (eg, company) [Default Company Ltd]: ')
    organizational_unit = input('Organizational Unit Name (eg, section) [Default Unit Name]: ')
    common_name = input('Common Name (eg, your name or your server\'s hostname) [Default Common Name]: ')
    email_address = input('Email Address [default@example.local]: ')

    cert = crypto.X509()
    cert.get_subject().countryName = country_name if country_name else 'XX'
    cert.get_subject().stateOrProvinceName = state_or_province if state_or_province else 'Default State/Province'
    cert.get_subject().localityName = locality_name if locality_name else 'Default City'
    cert.get_subject().organizationName = organization_name if organization_name else 'Default Company Ltd'
    cert.get_subject().organizationalUnitName = organizational_unit if organizational_unit else 'Default Unit Name'
    cert.get_subject().commonName = common_name if common_name else 'Default Common Name'
    cert.get_subject().emailAddress = email_address if email_address else 'default@example.local'
    cert.set_serial_number(serial_number)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(days * 86400)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha256')
    pub = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    priv = crypto.dump_privatekey(crypto.FILETYPE_PEM, k)

    with open(public_key, 'wt') as file_obj:
        file_obj.write(pub.decode('utf-8'))

    with open(private_key, 'wt') as file_obj:
        file_obj.write(priv.decode('utf-8'))


def encrypt_with_cert(msg, public_key):
    with open(public_key, 'r') as file_obj:
        public_key_data = file_obj.read()
    key = RSA.importKey(public_key_data)
    cipher = PKCS1_OAEP.new(key)
    encrypted_message = cipher.encrypt(msg.encode('utf-8'))
    return b64encode(encrypted_message).decode('utf-8')


def decrypt_with_cert(msg, private_key):
    with open(private_key, 'r') as file_obj:
        private_key_data = file_obj.read()
    key = RSA.importKey(private_key_data)
    cipher = PKCS1_OAEP.new(key)
    try:
        decrypted_message = cipher.decrypt(b64decode(msg))
    except ValueError:
        return 'Incorrect decryption key.'
    else:
        return decrypted_message.decode('utf-8')
