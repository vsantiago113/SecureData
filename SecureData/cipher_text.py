from Crypto.Cipher import AES
from Crypto import Random
from hashlib import md5
from base64 import b64encode, b64decode


def pad(msg):
    return msg.encode('utf-8') + b'\0' * (AES.block_size - len(msg) % AES.block_size)


def encrypt(key, msg, salt=None):
    key = key.encode('utf-8')
    msg = pad(msg)
    if salt:
        salt = salt.encode('utf-8')
        key = md5(key + salt).hexdigest().encode('utf-8')
    else:
        key = md5(key).hexdigest().encode('utf-8')
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, iv)

    return b64encode((iv + cipher.encrypt(msg)))


def decrypt(key, msg, salt=None):
    key = key.encode('utf-8')
    if salt:
        salt = salt.encode('utf-8')
        key = md5(key + salt).hexdigest().encode('utf-8')
    else:
        key = md5(key).hexdigest().encode('utf-8')
    msg = b64decode(msg)
    iv = msg[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CFB, iv)

    return cipher.decrypt(msg[AES.block_size:]).rstrip(b'\0')
