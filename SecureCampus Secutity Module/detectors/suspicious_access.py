from threat_detector import create_alert


def detect_unauthorized(role, endpoint):

    # ---------------- SAFE INPUT HANDLING ----------------
    if role is None:
        role = "UNKNOWN"
    elif not isinstance(role, str):
        role = str(role)

    if endpoint is None:
        endpoint = "/unknown"
    elif not isinstance(endpoint, str):
        endpoint = str(endpoint)

    role = role.strip().upper()
    endpoint = endpoint.strip().lower()

    # ---------------- PROTECTED ROUTES ----------------
    protected_routes = [
        "/admin",
        "/dashboard"
        
    ]

    # ---------------- CHECK ACCESS ----------------
    for route in protected_routes:

        if endpoint.startswith(route):

            # only ADMIN allowed
            if role != "ADMIN":

                return create_alert(
                    "UNAUTHORIZED_ACCESS",
                    "HIGH",
                    f"Unauthorized access attempt to {endpoint}"
                )

    return None