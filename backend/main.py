from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from fido2.webauthn import (
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    AttestationObject,
)
from fido2.server import Fido2Server
from fido2.utils import websafe_encode, websafe_decode
from starlette.middleware.sessions import SessionMiddleware
from fastapi.middleware.cors import CORSMiddleware
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

# CORS middleware should be added FIRST
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3334"],  # Replace with your frontend origin
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Session middleware should be added AFTER CORS
app.add_middleware(
    SessionMiddleware,
    secret_key="SUPERSECRET",  # Change this to a secure random key in production
)

rp = PublicKeyCredentialRpEntity(id="localhost", name="MyApp")
server = Fido2Server(rp)

users = {}


@app.post("/register/begin")
async def register_begin(request: Request):
    body = await request.json()
    username = body.get("username")
    if not username:
        raise HTTPException(status_code=400, detail="Username is required")

    user = PublicKeyCredentialUserEntity(
        id=username.encode("utf8"),
        name=username,
        display_name=username,
    )

    options, state = server.register_begin(
        user=user, credentials=[], user_verification="discouraged"
    )
    # Store the user info in the session state for later use
    state["user_id"] = username
    request.session["state"] = state
    logger.info(f"Set session state for {username}: {state}")
    logger.info(f"Session data: {request.session}")

    # Convert options to dictionary
    options_dict = {
        "publicKey": {
            "rp": {
                "id": options.public_key.rp.id,
                "name": options.public_key.rp.name,
            },
            "user": {
                "id": websafe_encode(options.public_key.user.id),
                "name": options.public_key.user.name,
                "displayName": options.public_key.user.display_name,
            },
            "challenge": websafe_encode(options.public_key.challenge),
            "pubKeyCredParams": [
                {
                    "type": param.type,
                    "alg": param.alg,
                }
                for param in options.public_key.pub_key_cred_params
            ],
            "timeout": options.public_key.timeout,
            "excludeCredentials": [
                {
                    "type": cred.type,
                    "id": websafe_encode(cred.id),
                    "transports": cred.transports,
                }
                for cred in options.public_key.exclude_credentials
            ],
            "authenticatorSelection": {
                "authenticatorAttachment": options.public_key.authenticator_selection.authenticator_attachment,
                "requireResidentKey": options.public_key.authenticator_selection.require_resident_key,
                "userVerification": options.public_key.authenticator_selection.user_verification,
            },
        }
    }
    return JSONResponse(content=options_dict)


@app.post("/register/complete")
async def register_complete(request: Request):
    body = await request.json()
    logger.info(f"Received body: {body}")
    logger.info(f"Session data: {request.session}")
    state = request.session.get("state")

    if not state:
        logger.error("No registration state found in session")
        logger.error(f"Current session: {dict(request.session)}")
        raise HTTPException(status_code=400, detail="No registration state found")

    try:
        # Extract credential data from the attestation object to get raw_id
        attestation_object_bytes = websafe_decode(body.get("attestationObject"))
        attestation_object = AttestationObject(attestation_object_bytes)

        # The raw_id is the credential_id from the attested credential data
        raw_id = attestation_object.auth_data.credential_data.credential_id

        # Prepare the RegistrationResponse structure that fido2 server expects
        registration_response = {
            "id": websafe_encode(raw_id),  # base64url encoded credential ID
            "rawId": websafe_encode(raw_id),  # base64url encoded raw credential ID
            "response": {
                "clientDataJSON": body.get(
                    "clientDataJSON"
                ),  # Keep as base64url string
                "attestationObject": body.get(
                    "attestationObject"
                ),  # Keep as base64url string
            },
            "type": "public-key",
        }

        # Call register_complete with the correct response structure
        auth_data = server.register_complete(state, registration_response)

        # Store the registered credential
        # Get the user_id from the session state that we stored in register_begin
        user_id = state.get("user_id").encode("utf8") if state.get("user_id") else None
        users[auth_data.credential_data.credential_id] = {
            "credential_data": auth_data.credential_data,
            "user_handle": user_id,  # Store the user_id from session
        }
        logger.info(
            f"Registered user with credential ID: {auth_data.credential_data.credential_id.hex()}"
        )
        logger.info(f"User handle: {user_id}")

        # Clear the session state after successful registration
        request.session.pop("state", None)

        return {"status": "ok"}

    except Exception as e:
        logger.error(f"Registration failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")


@app.post("/login/begin")
async def login_begin(request: Request):
    body = await request.json()
    username = body.get("username")
    if not username:
        raise HTTPException(status_code=400, detail="Username is required")

    credentials = []
    for cred in users.values():
        if cred["user_handle"] == username.encode("utf8"):
            credentials.append(cred["credential_data"])

    if not credentials:
        raise HTTPException(status_code=400, detail="No credentials found for user")

    options, state = server.authenticate_begin(credentials)
    request.session["state"] = state
    logger.info(f"Set login state for {username}: {state}")

    # Convert options to dictionary
    options_dict = {
        "publicKey": {
            "challenge": websafe_encode(options.public_key.challenge),
            "timeout": options.public_key.timeout,
            "rpId": options.public_key.rp_id,
            "allowCredentials": [
                {
                    "type": cred.type,
                    "id": websafe_encode(cred.id),
                    "transports": cred.transports or [],
                }
                for cred in options.public_key.allow_credentials
            ],
            "userVerification": options.public_key.user_verification,
        }
    }
    return JSONResponse(content=options_dict)


@app.post("/login/complete")
async def login_complete(request: Request):
    body = await request.json()
    logger.info(f"Received login body: {body}")
    state = request.session.get("state")
    if not state:
        raise HTTPException(status_code=400, detail="No authentication state found")

    try:
        credential_id = websafe_decode(body.get("credentialId"))

        # Prepare the AuthenticationResponse structure that fido2 server expects
        authentication_response = {
            "id": body.get("credentialId"),  # Keep as base64url string
            "rawId": body.get("credentialId"),  # Keep as base64url string
            "response": {
                "clientDataJSON": body.get(
                    "clientDataJSON"
                ),  # Keep as base64url string
                "authenticatorData": body.get(
                    "authenticatorData"
                ),  # Keep as base64url string
                "signature": body.get("signature"),  # Keep as base64url string
            },
            "type": "public-key",
        }

    except Exception as e:
        logger.error(f"Failed to decode login data: {str(e)}")
        raise HTTPException(status_code=400, detail="Invalid login data")

    auth_data = None
    for cred in users.values():
        if cred["credential_data"].credential_id == credential_id:
            auth_data = cred["credential_data"]
            break
    if not auth_data:
        raise HTTPException(status_code=400, detail="Unknown credential")

    try:
        server.authenticate_complete(
            state,
            [auth_data],
            authentication_response,
        )
    except Exception as e:
        logger.error(f"Authentication failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Authentication failed: {str(e)}")

    # Clear the session state after successful authentication
    request.session.pop("state", None)

    return {"status": "ok"}
