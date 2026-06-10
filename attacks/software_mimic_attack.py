# Simulates a software-based mimic attack using a forged fingerprint and valid cryptographic credentials.

import time
import numpy as np
import hmac
import hashlib
from device import FEATURE_COLUMNS

def run_mimic_attack(device, server):

    # Attacker guesses fingerprint (static approximation)
    sample_fp = device.device_data.sample(1)[FEATURE_COLUMNS].astype(float).values  # shape (1, 10)

    # Use a fresh nonce to avoid replay detection
    nonce = int(time.time()) % 10000
    timestamp = int(time.time())

    # Generate a valid signature assuming the attacker knows the device secret
    signature = hmac.new(
        device.secret.encode(),
        f"{device.device_id}|{timestamp}|{nonce}|{sample_fp.tolist()}".encode(),
        hashlib.sha256
    ).hexdigest()

    # Construct a forged authentication request
    fake_req = {
        "device_id": device.device_id,
        "timestamp": timestamp,
        "nonce": nonce,
        "fingerprint": sample_fp,
        "signature": signature
    }

    # Send the forged request for authentication
    status, result = server.verify(fake_req, device)

    return status, result