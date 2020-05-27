import json
import boto3
import json
import botocore.vendored.requests as requests
import os
from slack import WebClient
from slack.errors import SlackApiError


def lambda_handler(event, context):
    imagedigest = event["detail"]["image-digest"]
    imagetags = event["detail"]["image-tags"]
    repo = event["detail"]["repository-name"]

    client = boto3.client("ecr")

    response = client.describe_image_scan_findings(
        repositoryName=str(repo), imageId={"imageDigest": str(imagedigest)}
    )

    values = str(response["imageScanFindings"]["findings"])
    findings = response["imageScanFindings"]["findings"]
    findings = sorted(findings, key=take_cvs_score, reverse=True)
    
    # Count findings with medium or higher severity
    count = values.count("CRITICAL") + values.count("HIGH") + values.count("MEDIUM")

    # Figure out the highest severity
    if values.count("CRITICAL") > 0:
        severity = "Critical"
    elif values.count("HIGH") > 0:
        severity = "High"
    elif values.count("MEDIUM") > 0:
        severity = "Medium"
    else:
        severity = "Low"

    # Create initial text says whichs image and repos is scanned and which severity it got
    intro = (
        "Just scanned repo: "
        + repo
        + " with tags: "
        + str(imagetags)
        + " and found "
        + str(count)
        + " issues that should be looked at and with highest severity of "
        + severity
    )

    # If any CVEs with higher than or equal to medium post a message to slack about it
    if count > 0:
        client = WebClient(token=os.environ["BOT_TOKEN"])
        try:
            response = client.chat_postMessage(channel=os.environ["slackChannel"], text=str(intro))
            threadid = response["message"]["ts"]
            assert response["message"]["text"] == str(intro)
        except SlackApiError as e:
            # You will get a SlackApiError if "ok" is False
            assert e.response["error"]  # str like 'invalid_auth', 'channel_not_found'
            print(f"Got an error: {e.response['error']}")

        # To get around slack API throtling limit, bulk the messages together 10 at a time
        bulk_cves = 0
        cve_text = ""
        for cves in findings:
            bulk_cves += 1

            # Generate a message as a reply to the scan thread with info about the issues found
            cve_text = str(
                cve_text
                + str(cves["name"])
                + " "
                + str(cves["severity"])
                + ":\n"
                + str(cves["description"])
                + "\n"
                + str(cves["uri"])
                + "\n\n"
            )
            if bulk_cves > 9:
                try:
                    response = client.chat_postMessage(
                        channel="#ecr-scans", text=cve_text, thread_ts=threadid
                    )
                    # assert response["message"]["text"] == cve_text
                except SlackApiError as e:
                    # You will get a SlackApiError if "ok" is False
                    assert e.response["ok"] is False
                    assert e.response[
                        "error"
                    ]  # str like 'invalid_auth', 'channel_not_found'
                    print(f"Got an error: {e.response['error']}")
                bulk_cves = 0
                cve_text = ""
    else:
        return {
            "statusCode": 200,
            "body": "Nothing to report"
        }

    return {
        "statusCode": 200,
        #'body': json.dumps('Just scanned ' + str(repo) + " with result\n" + str(count) + str(result))
        "body": json.dumps(findings),
    }


def take_cvs_score(element):
    sev = element["severity"]
    sev_quantify = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
        "INFORMATIONAL": 0
    }
    return sev_quantify[sev]


if __name__ == "__main__":
    mock_event = {
        "version": "0",
        "id": "85fc3613-e913-7fc4-a80c-a3753e4aa9ae",
        "detail-type": "ECR Image Scan",
        "source": "aws.ecr",
        "account": "303269352904",
        "time": "2019-10-29T02:36:48Z",
        "region": "eu-west-1",
        "resources": ["arn:aws:ecr:eu-west-1:303269352904:repository/test"],
        "detail": {
            "scan-status": "COMPLETE",
            "repository-name": "test",
            "finding-severity-counts": {"CRITICAL": 10, "MEDIUM": 9},
            "image-digest": "sha256:ca013ac5c09f9a9f6db8370c1b759a29fe997d64d6591e9a75b71748858f7da0",
            "image-tags": [],
        },
    }

    lambda_handler(event=mock_event, context=None)
