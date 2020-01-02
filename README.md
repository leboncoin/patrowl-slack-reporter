# Patrowl Slack Reporter

## Prerequisites

### On-premise

```
pip3 install -r requirements.txt

cp settings.py.sample settings.py
cp patrowl_asset_lifecycle_settings.py.sample patrowl_asset_lifecycle_settings.py

# Edit each settings.py
```

### AWS Lambda

```
mkdir build
cd build
rm ../patrowl_slack_reporter.zip

# Build third-party libraries
pip3 install -r ../requirements.txt --target ./package

cp ../patrowl-slack-reporter_lamba.py patrowl-slack-reporter.py

# Build archive with all dependencies
zip -r9 ../patrowl_slack_reporter.zip .
```

Terraform example :
```
resource "aws_lambda_function" "patrowl_slack_reporter" {
  filename         = "patrowl_slack_reporter.zip"
  function_name    = "patrowl_slack_reporter"
  role             = "${aws_iam_role.iam_for_lambda.arn}"
  handler          = "patrowl_slack_reporter.handler"
  source_code_hash = "${filebase64sha256("patrowl_slack_reporter.zip")}"
  runtime          = "python3.7"
  timeout          = 840
  environment {
    variables = {
      LIST_GROUP_ID        = "29,46,47,51,55,56"
      PATROWL_APITOKEN     = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
      PATROWL_PRIVATE_ENDPOINT = "http://192.168.0.1"
      PATROWL_PUBLIC_ENDPOINT  = "https://my.patrowl.domain.net"
      SLACK_CHANNEL        = "#my-favorite-chan"
      SLACK_ICON_EMOJI     = ":sweat_smile:"
      SLACK_USERNAME       = "PatrOwl Slack Reporter"
      SLACK_WEBHOOK        = "https://hooks.slack.com/services/XXXXX/YYYYY/zzzzzzzzzzzzzzzz"
    }
  }
}
```

## Usage

### On-premise

```
python3 patrowl-slack-reporter.py

python3 patrowl_asset_lifecycle.py
```

