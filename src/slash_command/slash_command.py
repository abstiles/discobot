import os
import json
import traceback
from datetime import datetime, timezone, timedelta

import beeline
import diceydice
from beeline.middleware.awslambda import beeline_wrapper
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

DISCORD_PUBLIC_KEY = os.environ["DISCORD_PUBLIC_KEY"]
DISCORD_CLIENT_ID = os.environ["DISCORD_CLIENT_ID"]
HONEYCOMB_API_KEY = os.environ.get("HONEYCOMB_API_KEY")

verify = VerifyKey(bytes.fromhex(DISCORD_PUBLIC_KEY)).verify

beeline.init(
    writekey=HONEYCOMB_API_KEY,
    dataset="discordbot-test",
    service_name="authorizer"
)


class BadTimestampError(Exception):
    pass


@beeline_wrapper
def lambda_handler(event, context):
    headers = {
        key.lower(): value
        for key, value in event["headers"].items()
    }
    signature = headers["x-signature-ed25519"]
    timestamp = headers["x-signature-timestamp"]
    body = event["body"]

    try:
        verify_timestamp(timestamp)
        verify(f"{timestamp}{body}".encode(), bytes.fromhex(signature))

    except BadSignatureError as exc:
        log_exception("app", exc)
        return {
            "statusCode": 401,
            "body": '{"error":"Bad signature."}'
        }

    except BadTimestampError as exc:
        log_exception("app", exc)
        return {
            "statusCode": 401,
            "body": '{"error":"Bad timestamp."}'
        }

    body = json.loads(event["body"])
    if body["type"] == 1:
        return {
            "statusCode": 200,
            "body": '{"type":1}'
        }
    elif body["type"] == 2:
        return handle_command(body)
    return {
        "statusCode": 500,
        "body": '{"message":"Unhandled interaction type."}'
    }


def handle_command(body):
    try:
        user = body["member"]["nick"]
        roll_expr = body["data"]["options"][0]["value"]
        result = diceydice.evaluate(roll_expr)
        content = f'{user} rolled `"{roll_expr}"`\nResult: {result}'
    except Exception as exc:
        content = ' '.join(exc.args)

    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "type": 4,
                "data": {"content": content},
            }
        ),
    }


def verify_timestamp(timestamp, time_limit=timedelta(minutes=5)):
    beeline.add_context_field(
        'signature.time_limit_seconds',
        time_limit.total_seconds()
    )
    try:
        message_dt = datetime.fromtimestamp(float(timestamp), tz=timezone.utc)
        beeline.add_context_field('signature.timestamp', message_dt.isoformat())
        now_dt = datetime.now(timezone.utc)
        beeline.add_context_field('signature.now', now_dt.isoformat())
        time_drift = now_dt - message_dt
        beeline.add_context_field(
            'signature.time_drift_seconds',
            time_drift.total_seconds()
        )
        if abs(time_drift) > time_limit:
            raise BadTimestampError("Timestamp out of range")

    except (ValueError, OverflowError) as exc:
        raise BadTimestampError("Invalid timestamp") from exc


def log_exception(name, exception):
    beeline.add_context({
        f"{name}.exception_type": str(type(exception)),
        f"{name}.exception_string": str(exception),
        f"{name}.exception_stacktrace": traceback.format_exc(),
    })
