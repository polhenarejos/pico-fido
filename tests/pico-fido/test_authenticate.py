
def test_authenticate(device):
    device.reset()
    REGRes,AUTData = device.register()

    credentials = [AUTData.credential_data]
    AUTRes = device.authenticate(credentials)
