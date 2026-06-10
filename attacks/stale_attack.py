# Simulates a stale request attack in which an expired request is sent for authentication.

import time

def run_stale_attack(device, server):
    # Generate a request with the original fingerprint
    req = device.send_request(add_noise=False)

    # Modify the timestamp to simulate an expired request
    req["timestamp"] -= 100

    # Send the modified request for authentication
    status, result = server.verify(req, device)

    return status, result