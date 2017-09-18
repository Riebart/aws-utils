#!/usr/bin/env python

import argparse
import os
import base64
import time
from contextlib import contextmanager
import boto3

AWS_CLOUDTRAIL_NAME = "OrganizationTrail"
AWS_CLOUDTRAIL_ROLE_NAME = "OrganizationCloudTrailLogs"
AWS_CLOUDTRAIL_CWL_POLICY_NAME = "PutCloudWatchLogs"

AWS_IAM_PROTECTION_POLICY_NAME = "ProtectedOrganizationResources"
AWS_IAM_USER_NAME = "Administrator"

AWS_CONFIG_SERVICE_ROLE_NAME = "AwsConfigServiceRole"
AWS_CONFIG_SERVICE_DELIVERY_POLICY_NAME = "AWSConfigDelivery"


def configure_cloudtrail(session, account_id, target_bucket):
    """
    Configure an all-region CloudTrail trail that syndicates to CloudWatch Logs as well.
    """
    print "Creating boto3 clients..."
    ctrail = session.client("cloudtrail")
    iam = session.client("iam")
    cwl = session.client("logs")
    print "Clients created."

    # Create a role for Cloudtrail to use when posting events to CloudWatch
    print "Creating CloudTrail -> CloudWatch role..."
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
    print "Attaching inline policy to role..."
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
    print "Role created and policy attached."

    print "Creating CloudWatch Logs log group"
    cwl.create_log_group(logGroupName="/aws/CloudTrail/%s" %
                         AWS_CLOUDTRAIL_NAME)

    print "Sleeping for 10 seconds while role propagates to global scope..."
    time.sleep(10)

    print "Creating trail..."
    success = True
    for i in range(50):
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
            break
        except Exception as e:
            print "Encountered exception creating trail, sleeping and trying again..."
            print repr(e)
            print str(e)
            print e.__dict__
            time.sleep(5.0)
    if not success:
        print "Trail not created successfully."
        exit(1)
    ctrail.start_logging(Name=AWS_CLOUDTRAIL_NAME)
    print "Trail created and started successfully."


def configure_admin_user(session, account_id, admin_role):
    """
    Configure an Administrator user with a strong password.
    """
    print "Creating IAM client..."
    iam = session.client("iam")
    print "Creating managed policy for protecting organization assets..."
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

    print "Creating user..."
    iam.create_user(UserName=AWS_IAM_USER_NAME)
    print "Attached AWS managed AdministratorAccess policy..."
    iam.attach_user_policy(
        UserName=AWS_IAM_USER_NAME,
        PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    iam.attach_user_policy(
        UserName=AWS_IAM_USER_NAME,
        PolicyArn="arn:aws:iam::%s:policy/%s" %
        (account_id, AWS_IAM_PROTECTION_POLICY_NAME))
    print "IAM user created and policies attached."

    password = base64.b64encode(os.urandom(32))
    iam.create_login_profile(
        UserName=AWS_IAM_USER_NAME,
        Password=password,
        PasswordResetRequired=True)
    print "IAM user (%s) password changed to:" % AWS_IAM_USER_NAME, password


def configure_ec2_spot_datafeed(session, bucket, regions):
    # These will eventually propagate across regions automatically, but this makes it explicit and
    # immediate.
    #
    # This will silently not work if the bucket isn't in the us-east-1 region.
    for region in regions:
        print "Creating EC2 spot datafeed in %s" % region
        ec2 = session.client("ec2", region_name=region)
        ec2.create_spot_datafeed_subscription(
            Bucket=bucket, Prefix="SpotDatafeed")


def configure_aws_configservice(session, account_id, bucket, regions):
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
    print "Sleeping while the AWS ConfigService role propagates to the global scope"
    time.sleep(25)

    for region in regions:
        config = session.client("config", region_name=region)
        print "Creating ConfigService in %s" % region
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
        channel_kwargs = {
            "DeliveryChannel": {
                "name": "default",
                "s3BucketName": bucket,
                "configSnapshotDeliveryProperties": {
                    "deliveryFrequency": "One_Hour"
                }
            }
        }
        print channel_kwargs
        config.put_delivery_channel(**channel_kwargs)
        config.start_configuration_recorder(
            ConfigurationRecorderName="default")


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
    print "\"%s\" in progress" % thing
    try:
        yield
    except Exception as e:
        print "\"%s\" failed" % thing
        # print {
        #     "ErrorRepr": repr(e),
        #     "ErrorDict": e.__dict__,
        #     "ErrorStr": str(e)
        # }
    else:
        print "\"%s\" succeeded" % thing


def cleanup(session, account_id, regions):
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
        "--target-cloudtrail-awsconfig-bucket",
        help="The bucket name to send CloudTrail ans ConfigService events to",
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
        print "WARNING Unable to check bucket location for spot datafeed. If the bucket is not in us-east-1, the spot datafeeds won't work."

    # Use STS with the available credentials to assume credentials in the given account.
    print "Assuming role in target account..."
    sts = boto3.client("sts")
    sts_kwargs = {
        "RoleArn":
        "arn:aws:iam::%s:role/%s" % (pargs.account_id, pargs.role_name),
        "RoleSessionName":
        "AccountConfiguration%s" % repr(time.time())
    }
    credentials = sts.assume_role(**sts_kwargs)
    print "Retrieved ephemeral credentials in target account"
    print "Creating session..."
    session = boto3.Session(
        aws_access_key_id=credentials["Credentials"]["AccessKeyId"],
        aws_secret_access_key=credentials["Credentials"]["SecretAccessKey"],
        aws_session_token=credentials["Credentials"]["SessionToken"])
    print "Session created."

    if pargs.cleanup:
        cleanup(session, pargs.account_id, regions)
    else:
        configure_cloudtrail(session, pargs.account_id,
                             pargs.target_cloudtrail_awsconfig_bucket)
        configure_admin_user(session, pargs.account_id, pargs.role_name)
        configure_ec2_spot_datafeed(session, pargs.target_spot_datafeed_bucket,
                                    regions)
        configure_aws_configservice(session, pargs.account_id,
                                    pargs.target_cloudtrail_awsconfig_bucket,
                                    regions)

        if pargs.service_control_policy_id is not None:
            print "Attaching Service Control Policy to account."
            org = boto3.client("organizations")
            org.attach_policy(
                PolicyId=pargs.service_control_policy_id,
                TargetId=str(pargs.account_id))

        print "Signin link: https://%s.signin.aws.amazon.com/console" % pargs.account_id


if __name__ == "__main__":
    __main()
