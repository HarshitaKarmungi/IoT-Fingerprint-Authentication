# Simulates a tampering attack in which the fingerprint is replaced with unrelated random values.

import time
import numpy as np

def run_tampering_attack(device, server):

    req = device.send_request(add_noise=False)

    original_fp = req["fingerprint"]
    fp_len = len(original_fp)

    # Replace the original fingerprint with unrelated random values
    tampered_fp = np.random.normal(0, 10, fp_len)

    req["fingerprint"] = tampered_fp

    # Keep protocol valid
    req["nonce"] += 123
    req["timestamp"] = time.time()

    # Send the modified request for authentication
    status, result = server.verify(req, device)

    return status, result