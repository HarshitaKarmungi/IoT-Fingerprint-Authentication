# Simulates a hardware-level impersonation attack in which one device attempts to authenticate as another device.

def run_hardware_mimic_attack(device_legit, device_attacker, server):

    # Attacker device generates fingerprint
    req = device_attacker.send_request(add_noise=False)

    # BUT claims to be legit device
    req["device_id"] = device_legit.device_id
    req["nonce"] += 9999

    # Send the modified request for authentication
    status, result = server.verify(req, device_legit)

    return status, result
