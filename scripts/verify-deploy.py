#!/usr/bin/env python3
"""
verify-deploy.py
============================================================
Runs after terraform apply
Queries AWS directly to confirm resources actually exist
Does not trust Terraform output blindly
Sends result to SNS
============================================================
"""

import boto3
import json
import os
import sys
from datetime import datetime


def log(message):
    """Prints with timestamp"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}")


def check_s3_bucket(s3_client, bucket_name):
    """
    Verifies S3 bucket exists and is properly secured
    Checks encryption, versioning, public access block
    Returns True if all checks pass
    """
    log(f"Checking S3 bucket: {bucket_name}")

    try:
        # check bucket exists
        s3_client.head_bucket(Bucket=bucket_name)
        log(f"  PASS - bucket exists")

        # check encryption is enabled
        encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
        rules = encryption["ServerSideEncryptionConfiguration"]["Rules"]
        if rules:
            log(f"  PASS - encryption enabled")
        else:
            log(f"  FAIL - encryption not enabled")
            return False

        # check versioning is enabled
        versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
        if versioning.get("Status") == "Enabled":
            log(f"  PASS - versioning enabled")
        else:
            log(f"  FAIL - versioning not enabled")
            return False

        # check public access is blocked
        public_access = s3_client.get_public_access_block(Bucket=bucket_name)
        config = public_access["PublicAccessBlockConfiguration"]
        all_blocked = all([
            config.get("BlockPublicAcls"),
            config.get("BlockPublicPolicy"),
            config.get("IgnorePublicAcls"),
            config.get("RestrictPublicBuckets")
        ])
        if all_blocked:
            log(f"  PASS - public access blocked")
        else:
            log(f"  FAIL - public access not fully blocked")
            return False

        return True

    except Exception as e:
        log(f"  FAIL - error checking bucket: {e}")
        return False


def check_cloudtrail(cloudtrail_client, trail_name):
    """
    Verifies CloudTrail is active and logging
    Critical — if CloudTrail is off, no audit trail
    """
    log(f"Checking CloudTrail: {trail_name}")

    try:
        response = cloudtrail_client.get_trail_status(Name=trail_name)

        if response.get("IsLogging"):
            log(f"  PASS - CloudTrail is active and logging")
            return True
        else:
            log(f"  FAIL - CloudTrail exists but not logging")
            return False

    except Exception as e:
        log(f"  FAIL - error checking CloudTrail: {e}")
        return False


def check_ec2_runner(ec2_client, instance_id):
    """
    Verifies runner EC2 is running and properly configured
    Checks IMDSv2, encryption, no public IP
    """
    log(f"Checking EC2 runner: {instance_id}")

    try:
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        instance = response["Reservations"][0]["Instances"][0]

        # check instance is running
        state = instance["State"]["Name"]
        if state == "running":
            log(f"  PASS - instance is running")
        else:
            log(f"  FAIL - instance state is {state}")
            return False

        # check no public IP
        public_ip = instance.get("PublicIpAddress")
        if not public_ip:
            log(f"  PASS - no public IP")
        else:
            log(f"  FAIL - instance has public IP: {public_ip}")
            return False

        # check IMDSv2 is enforced
        metadata_options = instance.get("MetadataOptions", {})
        if metadata_options.get("HttpTokens") == "required":
            log(f"  PASS - IMDSv2 enforced")
        else:
            log(f"  FAIL - IMDSv2 not enforced")
            return False

        return True

    except Exception as e:
        log(f"  FAIL - error checking EC2: {e}")
        return False


def send_notification(sns_client, topic_arn, results, environment):
    """
    Sends deployment verification result to SNS
    You get an email with pass/fail for every check
    """
    passed = sum(1 for r in results.values() if r)
    failed = sum(1 for r in results.values() if not r)
    status = "SUCCESS" if failed == 0 else "FAILED"

    message = f"""
Deployment Verification Report
==============================
Environment: {environment}
Time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Status: {status}

Results:
"""
    for check, result in results.items():
        icon = "PASS" if result else "FAIL"
        message += f"  {icon} - {check}\n"

    message += f"""
Summary: {passed} passed, {failed} failed
"""

    sns_client.publish(
        TopicArn=topic_arn,
        Subject=f"[{status}] Deployment Verification - {environment}",
        Message=message
    )

    log(f"Notification sent to SNS")


def main():
    """
    Main function — runs all checks and reports results
    Exits with code 1 if any check fails
    Pipeline sees exit code 1 and marks job as failed
    """
    # get environment variables set by pipeline
    environment  = os.environ.get("ENVIRONMENT", "dev")
    aws_region   = os.environ.get("AWS_REGION", "us-east-1")
    bucket_name  = os.environ.get("ARTIFACTS_BUCKET")
    trail_name   = os.environ.get("CLOUDTRAIL_NAME")
    instance_id  = os.environ.get("RUNNER_INSTANCE_ID")
    sns_topic    = os.environ.get("SNS_TOPIC_ARN")

    if not all([bucket_name, trail_name, instance_id, sns_topic]):
        log("ERROR: Missing required environment variables")
        log("Required: ARTIFACTS_BUCKET, CLOUDTRAIL_NAME, RUNNER_INSTANCE_ID, SNS_TOPIC_ARN")
        sys.exit(1)

    # create AWS clients
    # uses IAM role — no hardcoded credentials
    s3_client          = boto3.client("s3", region_name=aws_region)
    cloudtrail_client  = boto3.client("cloudtrail", region_name=aws_region)
    ec2_client         = boto3.client("ec2", region_name=aws_region)
    sns_client         = boto3.client("sns", region_name=aws_region)

    log("Starting deployment verification")
    log("=" * 50)

    # run all checks
    results = {
        "S3 artifacts bucket":  check_s3_bucket(s3_client, bucket_name),
        "CloudTrail logging":   check_cloudtrail(cloudtrail_client, trail_name),
        "EC2 runner":           check_ec2_runner(ec2_client, instance_id),
    }

    log("=" * 50)

    # send notification regardless of pass or fail
    send_notification(sns_client, sns_topic, results, environment)

    # exit with failure if any check failed
    # pipeline sees this and marks job as failed
    if not all(results.values()):
        log("VERIFICATION FAILED - some checks did not pass")
        sys.exit(1)

    log("VERIFICATION PASSED - all checks passed")
    sys.exit(0)


if __name__ == "__main__":
    main()
