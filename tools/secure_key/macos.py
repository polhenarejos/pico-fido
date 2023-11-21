import sys
import keyring

DOMAIN = "PicoKeys.com"
USERNAME = "Pico-Fido"

try:
    import keyring
    from keyrings.osx_keychain_keys.backend import OSXKeychainKeysBackend, OSXKeychainKeyType, OSXKeyChainKeyClassType
except:
    print('ERROR: keyring module not found! Install keyring package.\nTry with `pip install keyrings.osx-keychain-keys`')
    sys.exit(-1)

try:
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
except:
    print('ERROR: cryptography module not found! Install cryptography package.\nTry with `pip install cryptography`')
    sys.exit(-1)


def get_backend(use_secure_enclave=False):
    backend = OSXKeychainKeysBackend(
        key_type=OSXKeychainKeyType.EC, # Key type, e.g. RSA, RC, DSA, ...
        key_class_type=OSXKeyChainKeyClassType.Private, # Private key, Public key, Symmetric-key
        key_size_in_bits=256,
        is_permanent=True, # If set, saves the key in keychain; else, returns a transient key
        use_secure_enclave=use_secure_enclave, # Saves the key in the T2 (TPM) chip, requires a code-signed interpreter
        access_group=None, # Limits key management and retrieval to set group, requires a code-signed interpreter
        is_extractable=True # If set, private key is extractable; else, it can't be retrieved, but only operated against
    )
    return backend

def generate_secure_key(use_secure_enclave=False):
    backend = get_backend(use_secure_enclave)
    backend.set_password(DOMAIN, USERNAME, password=None)
    return backend.get_password(DOMAIN, USERNAME)

def get_d(key):
    return key.private_numbers().private_value.to_bytes(32, 'big')

def set_secure_key(pk):
    backend = get_backend(False)
    try:
        backend.delete_password(DOMAIN, USERNAME)
    except:
        pass
    backend.set_password(DOMAIN, USERNAME, pk.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()))

def get_secure_key():
    key = None
    try:
        backend = get_backend(False)
        key = backend.get_password(DOMAIN, USERNAME)[0]
        if (key is None):
            raise TypeError
    except (keyring.errors.KeyringError, TypeError):
        try:
            key = generate_secure_key(False)[0] # It should be True, but secure enclave causes python segfault
        except keyring.errors.PasswordSetError:
            key = generate_secure_key(False)[0]
    return get_d(key)
