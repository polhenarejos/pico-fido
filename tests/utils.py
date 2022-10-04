from fido2.webauthn import AttestedCredentialData
import random
import string
import secrets
import math

def verify(MC, GA, client_data_hash):
    credential_data = AttestedCredentialData(MC.auth_data.credential_data)
    GA.verify(client_data_hash, credential_data.public_key)


def generate_random_user():
    # https://www.w3.org/TR/webauthn/#user-handle
    user_id_length = random.randint(1, 64)
    user_id = secrets.token_bytes(user_id_length)

    # https://www.w3.org/TR/webauthn/#dictionary-pkcredentialentity
    name = "User name"
    display_name = "Displayed " + name

    return {"id": user_id, "name": name, "displayName": display_name}

counter = 1
def generate_user_maximum():
    """
    Generate RK with the maximum lengths of the fields, according to the minimal requirements of the FIDO2 spec
    """
    global counter

    # https://www.w3.org/TR/webauthn/#user-handle
    user_id_length = 64
    user_id = secrets.token_bytes(user_id_length)

    # https://www.w3.org/TR/webauthn/#dictionary-pkcredentialentity
    name = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(64))

    name = f"{counter}: {name}"
    icon = "https://www.w3.org/TR/webauthn/" + "A" * 128
    display_name = "Displayed " + name

    name = name[:64]
    display_name = display_name[:64]
    icon = icon[:128]

    counter += 1

    return {"id": user_id, "name": name, "icon": icon, "displayName": display_name}

def shannon_entropy(data):
    s = 0.0
    total = len(data)
    for x in range(0, 256):
        freq = data.count(x)
        p = freq / total
        if p > 0:
            s -= p * math.log2(p)
    return s

