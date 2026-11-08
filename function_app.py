"""Discord HTTP interaction endpoint running as an Azure Function."""
import json
import logging
import os
import time

"""
Test for me :)
"""
import azure.functions as func
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from game import coinflip
from storage import get_balance, set_balance

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)


def _reply(message: str, *, private: bool = False) -> func.HttpResponse:
    data = {"content": message, "allowed_mentions": {"parse": []}}
    if private:
        data["flags"] = 64  # Discord ephemeral interaction message
    return func.HttpResponse(
        json.dumps({"type": 4, "data": data}),
        mimetype="application/json",
        status_code=200,
    )


def _valid_signature(req: func.HttpRequest) -> bool:
    """Discord signs timestamp + original raw request body using Ed25519."""
    public_key = os.getenv("DISCORD_PUBLIC_KEY", "").strip()
    signature = req.headers.get("X-Signature-Ed25519", "")
    timestamp = req.headers.get("X-Signature-Timestamp", "")
    if not public_key or not signature or not timestamp:
        return False
    try:
        # Reject old signed requests; this is NOT complete duplicate protection.
        if abs(time.time() - int(timestamp)) > 300:
            return False
        verify_key = VerifyKey(bytes.fromhex(public_key))
        verify_key.verify(timestamp.encode("utf-8") + req.get_body(), bytes.fromhex(signature))
        return True
    except (ValueError, TypeError, BadSignatureError):
        return False


@app.route(route="discord", methods=["POST"])
def discord_interactions(req: func.HttpRequest) -> func.HttpResponse:
    # Anonymous HTTP access is required by Discord; the signature check authenticates it.
    if not _valid_signature(req):
        return func.HttpResponse("Invalid Discord signature", status_code=401)

    try:
        payload = req.get_json()
    except ValueError:
        return func.HttpResponse("Invalid JSON", status_code=400)

    if payload.get("type") == 1:  # Discord's endpoint verification PING
        return func.HttpResponse('{"type": 1}', mimetype="application/json")
    if payload.get("type") != 2:
        return _reply("Unsupported interaction.", private=True)

    command = payload.get("data", {}).get("name", "")
    user = payload.get("member", {}).get("user") or payload.get("user") or {}
    user_id = user.get("id")
    if not user_id:
        return _reply("Could not identify user.", private=True)

    if command == "ping":
        return _reply("Pong! Your Discord request reached Azure Functions. ☁️")

    try:
        if command == "balance":
            balance = get_balance(user_id)
            return _reply(f"Your virtual balance: **{balance} credits**.", private=True)

        if command == "coinflip":
            options = {item["name"]: item["value"] for item in payload.get("data", {}).get("options", [])}
            # Server-side input validation is essential even when Discord defines choices.
            amount = options.get("amount")
            side = options.get("side")
            balance = get_balance(user_id)
            result = coinflip(balance, amount, side)
            set_balance(user_id, result["new_balance"])
            outcome = result["outcome"].capitalize()
            status = "You won" if result["won"] else "You lost"
            return _reply(
                f"🪙 **{outcome}!** {status} **{amount} virtual credits**. "
                f"New balance: **{result['new_balance']}**."
            )
    except ValueError as exc:
        return _reply(str(exc), private=True)
    except Exception:
        logging.exception("Discord command failed (no tokens or personal data logged)")
        return _reply("Cloud storage is unavailable. Ask the team to check Azure logs.", private=True)

    return _reply("Unknown command. Try /ping, /balance, or /coinflip.", private=True)
