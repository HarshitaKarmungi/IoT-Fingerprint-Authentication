# Simulates a noise attack in which additional fingerprint noise is added to the request.

def run_noise_attack(device, server):

    # Generate a request with additional fingerprint noise
    req = device.send_request(add_noise=True)

    # Send the modified request for authentication
    status, result = server.verify(req, device)

    return status, result