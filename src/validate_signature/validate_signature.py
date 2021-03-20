import os

import beeline

from beeline.middleware.awslambda import beeline_wrapper
from nacl.signing import VerifyKey

DISCORD_PUBLIC_KEY = os.environ["DISCORD_PUBLIC_KEY"]
DISCORD_CLIENT_ID = os.environ["DISCORD_CLIENT_ID"]
HONEYCOMB_API_KEY = os.environ.get("HONEYCOMB_API_KEY")
USAGE_PLAN_API_KEY = os.environ.get("USAGE_PLAN_API_KEY")

verify = VerifyKey(bytes.fromhex(DISCORD_PUBLIC_KEY)).verify

beeline.init(
    writekey=HONEYCOMB_API_KEY,
    dataset="discordbot-test",
    service_name="authorizer"
)

@beeline_wrapper
def lambda_handler(event, context):
    headers = {
        key.lower(): value
        for key, value in event["headers"].items()
    }
    signature = headers["x-signature-ed25519"]
    timestamp = headers["x-signature-timestamp"]
    body = event["body"]
    verify(f"{timestamp}{body}".encode(), bytes.fromhex(signature))

    policy = {
        "principalId": f"DiscordBot|{DISCORD_CLIENT_ID}",
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": "Allow",
                    "Resource": event["methodArn"]
                }
            ]
        },
    }

    if honeycomb_propagation_header := beeline.http_trace_propagation_hook():
        header, value = list(honeycomb_propagation_header.items())[0]
        policy["context"] = {
            "honeycomb_header": header,
            "honeycomb_value": value,
        }

    if USAGE_PLAN_API_KEY:
        policy["usageIdentifierKey"] = USAGE_PLAN_API_KEY

    return policy
