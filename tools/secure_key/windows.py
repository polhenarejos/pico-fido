import sys

DOMAIN = "PicoKeys.com"
USERNAME = "Pico-Fido"

try:
    import keyring
except:
    print('ERROR: keyring module not found! Install keyring package.\nTry with `pip install keyring`')
    sys.exit(-1)

try:
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, load_pem_private_key
    from cryptography.hazmat.primitives.asymmetric import ec
except:
    print('ERROR: cryptography module not found! Install cryptography package.\nTry with `pip install cryptography`')
    sys.exit(-1)



def generate_secure_key():
    pkey = ec.generate_private_key(ec.SECP256R1())
    set_secure_key(pkey)
    return keyring.get_password(DOMAIN, USERNAME)

def get_d(key):
    return load_pem_private_key(key, password=None).private_numbers().private_value.to_bytes(32, 'big')

def set_secure_key(pk):
    try:
        keyring.delete_password(DOMAIN, USERNAME)
    except:
        pass
    keyring.set_password(DOMAIN, USERNAME, pk.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode())

def get_secure_key():
    key = None
    try:
        key = keyring.get_password(DOMAIN, USERNAME)
        if (key is None):
            raise TypeError
    except (keyring.errors.KeyringError, TypeError):
        key = generate_secure_key()
    return get_d(key.encode())
