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
HELP_TEXT = '''
Basic dice format syntax:
* `XdY` - roll `X` dice with `Y` sides each.
* `XdYh` - roll `X` dice with `Y` sides each, keeping only the highest value rolled.
* `XdYhZ` - roll `X` dice with `Y` sides each, keeping only the `Z` highest values rolled.
* `XdYl` - roll `X` dice with `Y` sides each, keeping only the lowest value rolled.
* `XdYlZ` - roll `X` dice with `Y` sides each, keeping only the `Z` lowest values rolled.

Examples:
* `/dice 4d6` - roll four 6-sided dice, adding all the results together
* `/dice 2d20l` - roll two 20-sided dice, keeping only the low value
* `/dice 4d20h2` - roll four 20-sided dice, adding the two highest values together

Add multiple dice rolls together with `+` or group them with `()`.

Examples:
* `/dice 1d20 + 1d6` - roll a d20 and a d6, adding their values together
* `/dice (1d2 + 1d4 + 1d6 + 1d8)h` - roll four dice, keeping only the highest value
* `/dice 1d20 + (1d2 + 1d4 + 1d6 + 1d8)h` - add the d20 to the highest of the other four dice

Special dice:
* `Xc` - roll `X` combat/challenge dice, as used by the 2d20 system

Examples:
* `/dice 4c` - roll 4 combat/challenge dice, counting their results and showing those rolled with effects
'''

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
        roll_expr = body["data"]["options"][0]["value"].strip()
        if roll_expr:
            result = diceydice.evaluate(roll_expr)
            content = f'{user} rolled `"{roll_expr}"`\nResult: {result}'
        else:
            content = HELP_TEXT
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
