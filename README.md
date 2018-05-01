# TrailScraper

[![PyPi Release](https://img.shields.io/pypi/v/trailscraper.svg)](https://pypi.python.org/pypi/trailscraper)
[![Build Status](https://travis-ci.org/flosell/trailscraper.svg?branch=master)](https://travis-ci.org/flosell/trailscraper)

A command-line tool to get valuable information out of AWS CloudTrail

## Installation

```bash
$ pip install trailscraper
```

## Usage

### Download some logs (including us-east-1 for global aws services)
```
$ trailscraper download --bucket some-bucket \
                        --account-id some-account-id \
                        --region some-other-region \ 
                        --region us-east-1 \
                        --from 'two days ago' \
                        --to 'now' \
```

# Find CloudTrail events and generate an IAM Policy (<0.5.0)
```
$ trailscraper generate-policy
{
    "Statement": [
        {
            "Action": [
                "ec2:DescribeInstances",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeSubnets",
                "ec2:DescribeVolumes",
                "ec2:DescribeVpcs",
            ],
            "Effect": "Allow",
            "Resource": [
                "*"
            ]
        },
        {
            "Action": [
                "sts:AssumeRole"
            ],
            "Effect": "Allow",
            "Resource": [
                "arn:aws:iam::1111111111:role/someRole"
            ]
        }
    ],
    "Version": "2012-10-17"
} 
```

### Find CloudTrail events matching a filter (>=0.5.0) (unreleased)

```
$ trailscraper select --filter-assumed-role-arn some-arn \ 
                      --from 'one hour ago' \ 
                      --to 'now'
{
  "Records": [
    {
      "eventTime": "2017-12-11T15:01:51Z",
      "eventSource": "autoscaling.amazonaws.com",
      "eventName": "DescribeLaunchConfigurations",
```

### Generate Policy from some CloudTrail records (>=0.5.0) (unreleased)

```
$ gzcat some-records.json.gz | trailscraper generate
{
    "Statement": [
        {
            "Action": [
                "ec2:DescribeInstances"
            ],
            "Effect": "Allow",
            "Resource": [
                "*"
            ]
        }
    ],
    "Version": "2012-10-17"
} 
```

### Find CloudTrail events and generate an IAM Policy (>=0.5.0) (unreleased)
```
$ trailscraper select | trailscraper generate
{
    "Statement": [
        {
            "Action": [
                "ec2:DescribeInstances",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeSubnets",
                "ec2:DescribeVolumes",
                "ec2:DescribeVpcs",
            ],
            "Effect": "Allow",
            "Resource": [
                "*"
            ]
        },
        {
            "Action": [
                "sts:AssumeRole"
            ],
            "Effect": "Allow",
            "Resource": [
                "arn:aws:iam::1111111111:role/someRole"
            ]
        }
    ],
    "Version": "2012-10-17"
} 
```

## Development

```bash
$ ./go setup   # set up venv, dependencies and tools
$ ./go test    # run some tests
$ ./go check   # run some style checks
$ ./go         # let's see what we can do here
```

### FAQ

#### How can I generate policies in CloudFormation YAML instead of JSON? 

TrailScraper doesn't provide this. But you can use [cfn-flip](https://github.com/awslabs/aws-cfn-template-flip) to do it:

```
$ trailscraper select | trailscraper generate | cfn-flip
Statement:
  - Action:
      - ec2:DescribeInstances
    Effect: Allow
    Resource:
      - '*'
```

#### How can I generate policies in Terraform HCL instead of JSON? 

TrailScraper doesn't provide this. But you can use [iam-policy-json-to-terraform](https://github.com/flosell/iam-policy-json-to-terraform) to do it:

```
$ trailscraper select | trailscraper generate | iam-policy-json-to-terraform
data "aws_iam_policy_document" "policy" {
  statement {
    sid       = ""
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "ec2:DescribeInstances",
    ]
  }
}
```

### Troubleshooting

#### TrailScraper is missing some events

* Make sure you have logs for the `us-east-1` region. Some global AWS services (e.g. Route53, IAM, STS, CloudFront) use this region. For details, check the [CloudTrail Documentation](http://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html#cloudtrail-concepts-global-service-events)

#### TrailScraper generated actions that aren't IAM actions

This is totally possible. Unfortunately, there is no good, machine-readable documentation on how CloudTrail events
map to IAM actions so TrailScraper is using heuristics to figure out the right actions. These heuristics likely don't
cover all special cases of the AWS world.

This is where you come in: If you find a special case that's not covered by TrailScraper, 
please [open a new issue](https://github.com/flosell/trailscraper/issues/new) or, even better, submit a pull request.

For more details, check out the [contribution guide](./CONTRIBUTING.md) 

#### Click thinks you are in an ASCII environment 

`Click will abort further execution because Python 3 was configured to use ASCII as encoding for the environment.`

Set environment variables that describe your locale, e.g. :
```
export LC_ALL=de_DE.utf-8
export LANG=de_DE.utf-8
```
or 
```
LC_ALL=C.UTF-8
LANG=C.UTF-8
```
For details, see http://click.pocoo.org/5/python3/#python-3-surrogate-handling

