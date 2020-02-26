# Patrowl Slack Reporter

## Prerequisites

### On-premise

```
pip3 install -r requirements.txt

cp settings.py.sample settings.py

# Edit settings.py
```

### AWS Lambda

```
mkdir build
cd build
rm ../patrowl_slack_reporter.zip

# Build third-party libraries
pip3 install -r ../requirements.txt --target ./package

cp ../patrowl_slack_alert.py.lambda patrowl_slack_alert.py

# Build archive with all dependencies
zip -r9 ../patrowl_slack_reporter.zip .
```

Terraform example :
```
resource "aws_lambda_function" "patrowl_slack_alert" {
  filename         = "patrowl_slack_reporter.zip"
  function_name    = "patrowl_slack_alert"
  role             = "${aws_iam_role.iam_for_lambda.arn}"
  handler          = "patrowl_slack_alert.handler"
  source_code_hash = "${filebase64sha256("patrowl_slack_reporter.zip")}"
  runtime          = "python3.7"
  timeout          = 840
  environment {
    variables = {
      PATROWL_APITOKEN     = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
      PATROWL_PRIVATE_ENDPOINT = "http://192.168.0.1"
      PATROWL_PUBLIC_ENDPOINT  = "https://my.patrowl.domain.net"
      PSA_LIST_GROUP_ID        = "29,46,47,51,55,56"
      PSA_SLACK_ICON_EMOJI     = ":sweat_smile:"
      PSA_SLACK_USERNAME       = "PatrOwl Slack Reporter"
      SLACK_CHANNEL        = "#my-favorite-chan"
      SLACK_WEBHOOK        = "https://hooks.slack.com/services/XXXXX/YYYYY/zzzzzzzzzzzzzzzz"
    }
  }
}
```

## Usage

### On-premise

```
python3 patrowl_slack_alert.py

python3 patrowl_asset_lifecycle.py

python3 patrowl_threat_tagger.py
```
