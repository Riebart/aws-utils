#!/usr/bin/env python

import argparse
import os
import sys
import base64
import time
import yaml
from contextlib import contextmanager
import boto3

ROLE_PROPAGATION_TIMEOUT = 60

AWS_CLOUDTRAIL_NAME = "OrganizationTrail"
AWS_CLOUDTRAIL_ROLE_NAME = "OrganizationCloudTrailLogs"
AWS_CLOUDTRAIL_CWL_POLICY_NAME = "PutCloudWatchLogs"

AWS_IAM_PROTECTION_POLICY_NAME = "ProtectedOrganizationResources"
AWS_IAM_USER_NAME = "Administrator"

AWS_CONFIG_SERVICE_ROLE_NAME = "AwsConfigServiceRole"
AWS_CONFIG_SERVICE_DELIVERY_POLICY_NAME = "AWSConfigDelivery"


def configure_cloudtrail(session, account_id, target_bucket, in_use):
    """
    Configure an all-region CloudTrail trail that syndicates to CloudWatch Logs as well.
    """
    sys.stderr.write("Creating boto3 clients..." + "\n")
    ctrail = session.client("cloudtrail")
    iam = session.client("iam")
    cwl = session.client("logs")
    sys.stderr.write("Clients created." + "\n")

    # Create a role for Cloudtrail to use when posting events to CloudWatch
    sys.stderr.write("Creating CloudTrail -> CloudWatch role..." + "\n")
    iam.create_role(
        RoleName=AWS_CLOUDTRAIL_ROLE_NAME,
        Description="Role used by CloudTrail when posting events to CloudWatch",
        AssumeRolePolicyDocument="""{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "",
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "cloudtrail.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }
        """)
    sys.stderr.write("Attaching inline policy to role..." + "\n")
    r = iam.put_role_policy(
        RoleName=AWS_CLOUDTRAIL_ROLE_NAME,
        PolicyName=AWS_CLOUDTRAIL_CWL_POLICY_NAME,
        PolicyDocument="""{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AWSCloudTrailCreateLogStream",
                    "Effect": "Allow",
                    "Action": [
                        "logs:CreateLogStream"
                    ],
                    "Resource": [
                        "arn:aws:logs:us-east-1:%s:log-group:/aws/CloudTrail/%s:*"
                    ]
                },
                {
                    "Sid": "AWSCloudTrailPutLogEvents",
                    "Effect": "Allow",
                    "Action": [
                        "logs:PutLogEvents"
                    ],
                    "Resource": [
                        "arn:aws:logs:us-east-1:%s:log-group:/aws/CloudTrail/%s:*"
                    ]
                }
            ]
        }
        """ %
        (account_id, AWS_CLOUDTRAIL_NAME, account_id, AWS_CLOUDTRAIL_NAME))
    sys.stderr.write("Role created and policy attached." + "\n")

    sys.stderr.write("Creating CloudWatch Logs log group" + "\n")
    cwl.create_log_group(logGroupName="/aws/CloudTrail/%s" %
                         AWS_CLOUDTRAIL_NAME)

    sys.stderr.write(
        "Sleeping for 10 seconds while role propagates to global scope..." +
        "\n")
    role_put_time = time.time()

    sys.stderr.write("Creating trail..." + "\n")
    success = False
    while time.time(
    ) - role_put_time < ROLE_PROPAGATION_TIMEOUT and not success:
        try:
            ctrail.create_trail(
                Name=AWS_CLOUDTRAIL_NAME,
                S3BucketName=target_bucket,
                IncludeGlobalServiceEvents=True,
                IsMultiRegionTrail=True,
                EnableLogFileValidation=True,
                CloudWatchLogsLogGroupArn="arn:aws:logs:us-east-1:%s:log-group:/aws/CloudTrail/%s:*"
                % (account_id, AWS_CLOUDTRAIL_NAME),
                CloudWatchLogsRoleArn="arn:aws:iam::%s:role/%s" %
                (account_id, AWS_CLOUDTRAIL_ROLE_NAME))
            success = True
        except Exception as exc:
            if exc.response["Error"][
                    "Code"] == "InvalidCloudWatchLogsRoleArnException":
                sys.stderr.write("  Role not yet propagated..." + "\n")
            else:
                sys.stderr.write("Error creating cloudtrail trail" + "\n")
                sys.stderr.write(
                    str({
                        "ErrorRepr": repr(exc),
                        "ErrorStr": str(exc),
                        "ErrorDict": exc.__dict__
                    }) + "\n")
            time.sleep(5.0)

    if not success:
        sys.stderr.write("Trail not created successfully." + "\n")
        exit(1)
    ctrail.start_logging(Name=AWS_CLOUDTRAIL_NAME)
    sys.stderr.write("Trail created and started successfully." + "\n")


def configure_admin_user(session, account_id, admin_role, in_use):
    """
    Configure an Administrator user with a strong password.
    """
    sys.stderr.write("Creating IAM client..." + "\n")
    iam = session.client("iam")
    sys.stderr.write(
        "Creating managed policy for protecting organization assets..." + "\n")
    iam.create_policy(
        PolicyName=AWS_IAM_PROTECTION_POLICY_NAME,
        Description=(
            "Provides default-deny control over the Organization roles and resources that "
            "cannot be controlled through organization SCPs."),
        PolicyDocument="""{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Stmt1500485872000",
                    "Effect": "Deny",
                    "Action": [
                        "iam:*"
                    ],
                    "Resource": [
                        "arn:aws:iam::%s:role/%s",
                        "arn:aws:iam::%s:role/%s"
                    ]
                }
            ]
        }
        """ % (account_id, admin_role, account_id, AWS_CLOUDTRAIL_ROLE_NAME))

    sys.stderr.write("Creating user..." + "\n")
    iam.create_user(UserName=AWS_IAM_USER_NAME)
    sys.stderr.write("Attached AWS managed AdministratorAccess policy..." +
                     "\n")
    iam.attach_user_policy(
        UserName=AWS_IAM_USER_NAME,
        PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    iam.attach_user_policy(
        UserName=AWS_IAM_USER_NAME,
        PolicyArn="arn:aws:iam::%s:policy/%s" %
        (account_id, AWS_IAM_PROTECTION_POLICY_NAME))
    sys.stderr.write("IAM user created and policies attached." + "\n")

    password = base64.b64encode(os.urandom(32))
    iam.create_login_profile(
        UserName=AWS_IAM_USER_NAME,
        Password=password,
        PasswordResetRequired=True)
    sys.stderr.write("IAM user (%s) password changed to: %s" % (
        AWS_IAM_USER_NAME, password) + "\n")
    return password


def configure_ec2_spot_datafeed(session, bucket, regions, in_use):
    # These will eventually propagate across regions automatically, but this makes it explicit and
    # immediate.
    #
    # This will silently not work if the bucket isn't in the us-east-1 region.
    for region in regions:
        sys.stderr.write("Creating EC2 spot datafeed in %s" % region + "\n")
        ec2 = session.client("ec2", region_name=region)
        ec2.create_spot_datafeed_subscription(
            Bucket=bucket, Prefix="SpotDatafeed")


def configure_aws_configservice(session, account_id, bucket, regions, in_use):
    # Note that the target bucket, if it isn't in the same account, needs to have the right
    # permissions attached to it.
    #
    # Ref: http://docs.aws.amazon.com/config/latest/developerguide/s3-bucket-policy.html
    iam = session.client("iam")

    iam.create_role(
        RoleName=AWS_CONFIG_SERVICE_ROLE_NAME,
        Path="/service-role/",
        Description="Role assumed by AWS Config service",
        AssumeRolePolicyDocument="""{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "",
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "config.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }""")
    iam.put_role_policy(
        RoleName=AWS_CONFIG_SERVICE_ROLE_NAME,
        PolicyName=AWS_CONFIG_SERVICE_DELIVERY_POLICY_NAME,
        PolicyDocument="""{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:PutObject*"
                    ],
                    "Resource": [
                        "arn:aws:s3:::%s/AWSLogs/%s/*"
                    ],
                    "Condition": {
                        "StringLike": {
                            "s3:x-amz-acl": "bucket-owner-full-control"
                        }
                    }
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetBucketAcl"
                    ],
                    "Resource": "arn:aws:s3:::%s"
                }
            ]
        }""" % (bucket, account_id, bucket))
    iam.attach_role_policy(
        RoleName=AWS_CONFIG_SERVICE_ROLE_NAME,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSConfigRole")
    role_put_time = time.time()

    # Eventually, we'll successfully use this role, and at that time the timeout should be ignored
    role_put_confirmed = False

    for region in regions:
        # IAM roles take time to propagate to global scope (and even within the same region), so the
        # first few creations may fail (if the first one is in us-east-1 with the IAM endpoint, it
        # may succeed while the next one in another region may fail).
        #
        # In practice, all regions should have the role within 60 seconds (25 is usually enough, but
        # 60 seconds for a buffer of safety should be fine).
        config = session.client("config", region_name=region)
        sys.stderr.write("Creating ConfigService in %s" % region + "\n")

        # Keep track of how far into the creation process we get, don't try to retry parts of the
        # resources we successfully created.
        checkpoint = 0

        # Try to create resources in this region as long as the timeout hasn't passed
        while (time.time() - role_put_time < ROLE_PROPAGATION_TIMEOUT or
               role_put_confirmed) and checkpoint < 3:
            try:
                if checkpoint < 1:
                    sys.stderr.write("    Putting configuration recorder..." +
                                     "\n")
                    config.put_configuration_recorder(ConfigurationRecorder={
                        "name":
                        "default",
                        "roleARN":
                        "arn:aws:iam::%s:role/service-role/%s" %
                        (account_id, AWS_CONFIG_SERVICE_ROLE_NAME),
                        "recordingGroup": {
                            "allSupported": True,
                            # "includeGlobalResourceTypes": (region == "us-east-1") # Only record global services in us-east-1
                            "includeGlobalResourceTypes": True
                        }
                    })
                    checkpoint = 1
                elif checkpoint < 2:
                    channel_kwargs = {
                        "DeliveryChannel": {
                            "name": "default",
                            "s3BucketName": bucket,
                            "configSnapshotDeliveryProperties": {
                                "deliveryFrequency": "One_Hour"
                            }
                        }
                    }
                    sys.stderr.write("    Putting delivery channel..." + "\n")
                    config.put_delivery_channel(**channel_kwargs)
                    checkpoint = 2
                elif checkpoint < 3:
                    sys.stderr.write("    Starting configuration recorder..." +
                                     "\n")
                    config.start_configuration_recorder(
                        ConfigurationRecorderName="default")
                    checkpoint = 3
                    role_put_confirmed = True
            except Exception as exc:
                if exc.response["Error"][
                        "Code"] == "InsufficientDeliveryPolicyException":
                    sys.stderr.write("  Role not yet propagated..." + "\n")
                else:
                    sys.stderr.write(
                        "Error creating AWS Config resources at checkpoint %d"
                        % checkpoint + "\n")
                    sys.stderr.write(
                        str({
                            "ErrorRepr": repr(exc),
                            "ErrorStr": str(exc),
                            "ErrorDict": exc.__dict__
                        }) + "\n")
                time.sleep(5.0)

        if checkpoint < 3:
            # We timed out!
            sys.stderr.write(
                "Timeout attempting to create AWSConfigService resources in %s"
                % region + "\n")
            exit(1)


def aws_account_number(aan):
    """
    Confirm that the given string is a twelve-digit account number, stripping hyphens if they
    are present.
    """
    # Strip out hyphens
    account_id = aan.replace("-", "")

    # Confirm that it is numeric, when considered without hyphens
    try:
        int(account_id)
    except:
        raise ValueError(
            "Account ID must be a twelve digit account number, possibly with hyphens"
        )

    try:
        assert len(account_id) == 12
    except:
        raise ValueError(
            "Without hyphens, the account ID should be twelve digits")

    return aan.replace("-", "")


@contextmanager
def do_the_thing(thing):
    """
    Perform an operation that may except, ignoring any exception.
    """
    sys.stderr.write("\"%s\" in progress" % thing + "\n")
    try:
        yield
    except Exception as e:
        sys.stderr.write("\"%s\" failed" % thing + "\n")
    else:
        sys.stderr.write("\"%s\" succeeded" % thing + "\n")


def cleanup(session, account_id, regions, in_use):
    """
    Clean up all resources possibly created by a previous version of this script.
    """
    ctrail = session.client("cloudtrail", region_name="us-east-1")
    with do_the_thing("Stop CloudTrail Logging"):
        ctrail.stop_logging(Name=AWS_CLOUDTRAIL_NAME)
    with do_the_thing("Delete Trail"):
        ctrail.delete_trail(Name=AWS_CLOUDTRAIL_NAME)

    awslogs = session.client("logs", region_name="us-east-1")
    with do_the_thing("Delete CloudTrail Log Group"):
        awslogs.delete_log_group(logGroupName="/aws/CloudTrail/%s" %
                                 AWS_CLOUDTRAIL_NAME)

    for region in regions:
        ec2 = session.client("ec2", region_name=region)
        config = session.client("config", region_name=region)
        with do_the_thing("%s EC2 spot datafeed" % region):
            ec2.delete_spot_datafeed_subscription()
        with do_the_thing("%s stop config recorder" % region):
            config.stop_configuration_recorder(
                ConfigurationRecorderName="default")
        with do_the_thing("%s delete config recorder" % region):
            config.delete_configuration_recorder(
                ConfigurationRecorderName="default")
        with do_the_thing("%s delete config delivery channel" % region):
            config.delete_delivery_channel(DeliveryChannelName="default")

    iam = session.client("iam")
    if not in_use:
        with do_the_thing("Delete IAM User login profile"):
            iam.delete_login_profile(UserName=AWS_IAM_USER_NAME)
        with do_the_thing("Detach IAM user admin policy"):
            iam.detach_user_policy(
                UserName=AWS_IAM_USER_NAME,
                PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
        with do_the_thing("Detach IAM user restriction policy"):
            iam.detach_user_policy(
                UserName=AWS_IAM_USER_NAME,
                PolicyArn="arn:aws:iam::%s:policy/%s" %
                (account_id, AWS_IAM_PROTECTION_POLICY_NAME))
        with do_the_thing("Delete IAM User"):
            iam.delete_user(UserName=AWS_IAM_USER_NAME)
        with do_the_thing("Delete IAM Managed Policy"):
            iam.delete_policy(PolicyArn="arn:aws:iam::%s:policy/%s" %
                              (account_id, AWS_IAM_PROTECTION_POLICY_NAME))
    with do_the_thing("Delete CloudTrail CWL role policy"):
        iam.delete_role_policy(
            RoleName=AWS_CLOUDTRAIL_ROLE_NAME,
            PolicyName=AWS_CLOUDTRAIL_CWL_POLICY_NAME)
    with do_the_thing("Delete CloudTrail IAM Role"):
        iam.delete_role(RoleName=AWS_CLOUDTRAIL_ROLE_NAME)
    with do_the_thing("Delete ConfigService delivery role policy"):
        iam.delete_role_policy(
            RoleName=AWS_CONFIG_SERVICE_ROLE_NAME,
            PolicyName=AWS_CONFIG_SERVICE_DELIVERY_POLICY_NAME)
    with do_the_thing("Detach ConfigService managed role policy"):
        iam.detach_role_policy(
            RoleName=AWS_CONFIG_SERVICE_ROLE_NAME,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AWSConfigRole")
    with do_the_thing("Delete ConfigService IAM Role"):
        iam.delete_role(RoleName=AWS_CONFIG_SERVICE_ROLE_NAME)


def __main():
    parser = argparse.ArgumentParser(
        description="""Apply a standard set of configuration controls
    to the supplied AWS account.""")
    parser.add_argument(
        "--in-use",
        required=False,
        default=False,
        action="store_true",
        help="""Indicate whether the account is in use, in which case care should be taken
        regarding someresources.""")
    parser.add_argument(
        "--account-id",
        help="Twelve digit AWS account number",
        type=aws_account_number,
        required=True)
    parser.add_argument(
        "--role-name",
        help="The name of the role to assume inside the target account",
        default="OrganizationAccountAccessRole")
    parser.add_argument(
        "--service-control-policy-id",
        help="The AWS Organization policy to apply to the account",
        default=None,
        required=False)
    parser.add_argument(
        "--target-cloudtrail-bucket",
        help="The bucket name to send CloudTrail ans ConfigService events to.",
        required=True)
    parser.add_argument(
        "--target-awsconfig-bucket",
        help="The bucket name to send AWS ConfigService events to.",
        required=True)
    parser.add_argument(
        "--target-spot-datafeed-bucket",
        help="""The bucket name to send EC2 spot instance price datafeed log events to. The created
        datafeed will have the prefix of SpotDatafeed/<AccountId>.""",
        required=True)
    parser.add_argument(
        "--cleanup",
        help="Delete all resources that may have been created in a previous run of this tool.",
        action="store_true",
        required=False,
        default=False)
    pargs = parser.parse_args()

    ec2 = boto3.client("ec2")
    s3 = boto3.client("s3")
    regions = [r["RegionName"] for r in ec2.describe_regions()["Regions"]]
    try:
        if s3.get_bucket_location(Bucket=pargs.target_spot_datafeed_bucket)[
                "LocationConstraint"] is not None:
            raise AssertionError(
                "Unable to set spot datafeed, target bucket must be in us-east-1/US-STANDARD region."
            )
    except Exception as exc:
        sys.stderr.write((
            "WARNING Unable to check bucket location for spot datafeed."
            "If the bucket is not in us-east-1, the spot datafeeds won't work."
        ) + "\n")

    # Use STS with the available credentials to assume credentials in the given account.
    sys.stderr.write("Assuming role in target account..." + "\n")
    sts = boto3.client("sts")
    sts_kwargs = {
        "RoleArn":
        "arn:aws:iam::%s:role/%s" % (pargs.account_id, pargs.role_name),
        "RoleSessionName":
        "AccountConfiguration%s" % repr(time.time())
    }
    credentials = sts.assume_role(**sts_kwargs)
    sys.stderr.write("Retrieved ephemeral credentials in target account" +
                     "\n")
    sys.stderr.write("Creating session..." + "\n")
    session = boto3.Session(
        aws_access_key_id=credentials["Credentials"]["AccessKeyId"],
        aws_secret_access_key=credentials["Credentials"]["SecretAccessKey"],
        aws_session_token=credentials["Credentials"]["SessionToken"])
    sys.stderr.write("Session created." + "\n")

    if pargs.cleanup:
        cleanup(session, pargs.account_id, regions, pargs.in_use)
    else:
        configure_cloudtrail(session, pargs.account_id,
                             pargs.target_cloudtrail_bucket, pargs.in_use)
        user_password = configure_admin_user(session, pargs.account_id,
                                             pargs.role_name, pargs.in_use)
        configure_ec2_spot_datafeed(session, pargs.target_spot_datafeed_bucket,
                                    regions, pargs.in_use)
        configure_aws_configservice(session, pargs.account_id,
                                    pargs.target_awsconfig_bucket, regions,
                                    pargs.in_use)

        if pargs.service_control_policy_id is not None:
            sys.stderr.write("Attaching Service Control Policy to account." +
                             "\n")
            org = boto3.client("organizations")
            org.attach_policy(
                PolicyId=pargs.service_control_policy_id,
                TargetId=str(pargs.account_id))
            print yaml.safe_dump(
                org.describe_account(AccountId=pargs.account_id)["Account"],
                default_flow_style=False)

        print "Signin link: https://%s.signin.aws.amazon.com/console" % pargs.account_id
        print "Username: %s" % AWS_IAM_USER_NAME
        print "Password: %s" % user_password


if __name__ == "__main__":
    __main()
