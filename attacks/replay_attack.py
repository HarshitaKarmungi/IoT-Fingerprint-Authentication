# Simulates a replay attack in which a previously valid request is sent again.

def run_replay_attack(device, server):

    req = device.send_request(add_noise=False)

    # First time → should pass
    server.verify(req, device)

    # Replay same request
    status, result = server.verify(req, device)

    return status, result