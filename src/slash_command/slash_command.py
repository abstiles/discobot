import os
import json

import beeline

from beeline.middleware.awslambda import beeline_wrapper

HONEYCOMB_API_KEY = os.environ.get("HONEYCOMB_API_KEY")

beeline.init(
    writekey=HONEYCOMB_API_KEY,
    dataset="discordbot-test",
    service_name="authorizer"
)


@beeline_wrapper
def lambda_handler(event, context):
    if json.loads(event["body"])["type"] == 1:
        return {
            "statusCode": 200,
            "body": '{"type":1}'
        }
    return {
        "statusCode": 500,
        "body": '{"message":"Unhandled interaction type."}'
    }
