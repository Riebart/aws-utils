# AWS Organization Account Setup

This script is useful for setting up some good defaults in a new accounted created in an AWS organization.

It assumes a role in the new account, created a CloudTrail trail that logs to the specified bucket, creates a new Administrator user, applies a policy to help prevent accidental clobbering of Organization roles/assets, then applies an Organization level Service Control Policy to the account to prevent CloudTrail configuration modification.

A good suggested SCP is:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "Stmt1500475211000",
            "Effect": "Deny",
            "Action": [
                "cloudtrail:DeleteTrail",
                "cloudtrail:CreateTrail",
                "cloudtrail:StopLogging",
                "cloudtrail:UpdateTrail",
                "cloudtrail:PutEventSelectors",
                "cloudtrail:StartLogging",
                "cloudtrail:StopLogging",
                "config:StopConfigurationRecorder",
                "config:StartConfigurationRecorder",
                "config:PutDeliveryChannel",
                "config:DeleteConfigurationRecorder",
                "config:DeleteDeliveryChannel",
                "config:PutDeliveryChannel",
                "config:PutConfigurationRecorder",
                "ec2:CreateSpotDatafeedSubscription",
                "ec2:DeleteSpotDatafeedSubscription"
            ],
            "Resource": [
                "*"
            ]
        }
    ]
}
```
