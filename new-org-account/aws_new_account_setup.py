#!/usr/bin/env python

import argparse
import os
import base64
import time
import boto3


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
        RoleName="OrganizationCloudTrailLogs",
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
        RoleName="OrganizationCloudTrailLogs",
        PolicyName="PutCloudWatchLogs",
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
                        "arn:aws:logs:us-east-1:%d:log-group:/aws/CloudTrail/OrganizationTrail:*"
                    ]
                },
                {
                    "Sid": "AWSCloudTrailPutLogEvents",
                    "Effect": "Allow",
                    "Action": [
                        "logs:PutLogEvents"
                    ],
                    "Resource": [
                        "arn:aws:logs:us-east-1:%d:log-group:/aws/CloudTrail/OrganizationTrail:*"
                    ]
                }
            ]
        }
        """ % (account_id, account_id))
    print "Role created and policy attached."

    print "Creating CloudWatch Logs log group"
    cwl.create_log_group(logGroupName="/aws/CloudTrail/OrganizationTrail")

    print "Sleeping for 10 seconds while role propagates to global scope..."
    time.sleep(10)

    print "Creating trail..."
    success = True
    for i in range(50):
        try:
            ctrail.create_trail(
                Name="OrganizationTrail",
                S3BucketName=target_bucket,
                IncludeGlobalServiceEvents=True,
                IsMultiRegionTrail=True,
                EnableLogFileValidation=True,
                CloudWatchLogsLogGroupArn="arn:aws:logs:us-east-1:%d:log-group:/aws/CloudTrail/OrganizationTrail:*"
                % account_id,
                CloudWatchLogsRoleArn="arn:aws:iam::%d:role/OrganizationCloudTrailLogs"
                % account_id)
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
    ctrail.start_logging(Name="OrganizationTrail")
    print "Trail created and started successfully."


def configure_admin_user(session, account_id):
    """
    Configure an Administrator user with a strong password.
    """
    print "Creating IAM client..."
    iam = session.client("iam")
    print "Creating managed policy for protecting organization assets..."
    iam.create_policy(
        PolicyName="ProtectedOrganizationResources",
        Description="Provides default-deny control over the Organization roles and resources that cannot be controlled through organization SCPs.",
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
                        "arn:aws:iam::%d:role/OrganizationAccountAccessRole",
                        "arn:aws:iam::%d:role/OrganizationCloudTrailLogs"
                    ]
                }
            ]
        }
        """ % (account_id, account_id))

    print "Creating user..."
    iam.create_user(UserName="Administrator")
    print "Attached AWS managed AdministratorAccess policy..."
    iam.attach_user_policy(
        UserName="Administrator",
        PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    iam.attach_user_policy(
        UserName="Administrator",
        PolicyArn="arn:aws:iam::%d:policy/ProtectedOrganizationResources" %
        account_id)
    print "IAM user created and policies attached."

    password = base64.b64encode(os.urandom(32))
    iam.create_login_profile(
        UserName="Administrator",
        Password=password,
        PasswordResetRequired=True)
    print "IAM user password changed to:", password


def __main():
    parser = argparse.ArgumentParser(
        description="""Apply a standard set of configuration controls
    to the supplied AWS account.""")
    parser.add_argument(
        "--account-id",
        help="Twelve digit AWS account number",
        type=int,
        required=True)
    parser.add_argument(
        "--role-name",
        help="The name of the role to assume inside the target account",
        default="OrganizationAccountAccessRole")
    parser.add_argument(
        "--service-control-policy-id",
        help="The AWS Organization policy to apply to the account",
        required=True)
    parser.add_argument(
        "--target-bucket",
        help="The bucket name to send CloudTrail log events to",
        required=True)
    pargs = parser.parse_args()

    # Use STS with the available credentials to assume credentials in the given account.
    print "Assuming role in target account..."
    sts = boto3.client('sts')
    credentials = sts.assume_role(
        RoleArn="arn:aws:iam::%d:role/%s" %
        (pargs.account_id, pargs.role_name),
        RoleSessionName="AccountConfiguration")
    print "Retrieved ephemeral credentials in target account"
    print "Creating session..."
    session = boto3.Session(
        aws_access_key_id=credentials["Credentials"]["AccessKeyId"],
        aws_secret_access_key=credentials["Credentials"]["SecretAccessKey"],
        aws_session_token=credentials["Credentials"]["SessionToken"])
    print "Session created."

    configure_cloudtrail(session, pargs.account_id, pargs.target_bucket)
    configure_admin_user(session, pargs.account_id)

    print "Attaching CloudTrailSteadyState policy to account."
    org = boto3.client("organizations")
    org.attach_policy(
        PolicyId=pargs.service_control_policy_id,
        TargetId=str(pargs.account_id))

    print "Signin link: https://%d.signin.aws.amazon.com/console" % pargs.account_id


if __name__ == "__main__":
    __main()
