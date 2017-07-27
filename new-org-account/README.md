# AWS Organization Account Setup

This script is useful for setting up some good defaults in a new accounted created in an AWS organization.

It assumes a role in the new account, created a CloudTrail trail that logs to the specified bucket, creates a new Administrator user, applies a policy to help prevent accidental clobbering of Organization roles/assets, then applies an Organization level Service Control Policy to the account to prevent CloudTrail configuration modification.

A good suggested SCP is:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "Stmt1493438668000",
            "Effect": "Deny",
            "Action": [
                "cloudtrail:AddTags",
                "cloudtrail:CreateTrail",
                "cloudtrail:DeleteTrail",
                "cloudtrail:PutEventSelectors",
                "cloudtrail:RemoveTags",
                "cloudtrail:StartLogging",
                "cloudtrail:StopLogging",
                "cloudtrail:UpdateTrail",
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
