# SecureData
A Python module to encrypt and decrypt data using passwords or certs.

---

### To generate an SSL Certificate
```python
from SecureData import cert

cert.generate_cert(days=365, size=2048, serial_number=123, public_key='mypub.crt', private_key='mypriv.key')
```
Answer all the prompts

---

### To encrypt data using an SSL Certificate
```python
from SecureData import cert

my_encrypted_text = cert.encrypt_with_cert('my secure text', 'mypub.crt')
print(my_encrypted_text)
```

---

### To decrypt data using an SSL Certificate
```python
from SecureData import cert

my_encrypted_text = '16as1dgf61asdf51as3d51fas35d1f6asef1'
my_plain_text = cert.decrypt_with_cert(my_encrypted_text, 'mypriv.key')
print(my_plain_text)
```

---

### To encrypt data using a password an an optional salt
```python
from SecureData import cipher_text

my_encrypted_text = cipher_text.encrypt('mypass', 'my message', salt='mysecretsalt')
print(my_encrypted_text)
```

---

### To decrypt data using a password an an optional salt
```python
from SecureData import cipher_text

my_encrypted_text = 'iTnh1SnjZWebURp9Ng/cXPG9q7n9BNmmj8RagAZCtE8='
my_plain_text = cipher_text.decrypt('mypass', my_encrypted_text)
print(my_plain_text)
```

---
