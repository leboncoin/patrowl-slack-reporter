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
rm ../patrowl_slack_alert.zip

# Build third-party libraries
pip3 install -r ../requirements.txt --target ./package

cp ../patrowl-slack-reporter_lamba.py patrowl-slack-reporter.py

# Build archive with all dependencies
zip -r9 ../patrowl_slack_alert.zip .
```

Terraform example :
```
resource "aws_lambda_function" "patrowl_slack_alert" {
  filename         = "patrowl_slack_alert.zip"
  function_name    = "patrowl_slack_alert"
  role             = "${aws_iam_role.iam_for_lambda.arn}"
  handler          = "patrowl_slack_alert.handler"
  source_code_hash = "${base64sha256("patrowl_slack_alert.zip")}"
  runtime          = "python3.7"
  timeout          = 840
  environment {
    variables = {
      DEBUG                = "False"
      EYEWITNESS_BASICAUTH = "False"
      EYEWITNESS_PASSWORD  = "pass"
      EYEWITNESS_POLICY    = "30"
      EYEWITNESS_USERNAME  = "user"
      FREQUENCY_SECOND     = "900"
      LIST_GROUP_ID        = "29,46,47,51,55,56"
      PATROWL_APITOKEN     = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
      PATROWL_ENDPOINT     = "http://192.168.0.1"
      SLACK_CHANNEL        = "#my-favorite-chan"
      SLACK_ICON_EMOJI     = ":sweat_smile:"
      SLACK_LEGACY_TOKEN   = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
      SLACK_PRETEXT        = "New domain identified"
      SLACK_USERNAME       = "PatrOwl Slack Reporter"
      SLACK_WEBHOOK        = "https://hooks.slack.com/services/XXXXX/YYYYY/zzzzzzzzzzzzzzzz"
      TIMEZONE             = "Europe/Paris"
      VIRUSTOTAL_POLICY    = "38"
    }
  }
}
```

## Usage

### On-premise

```
python3 patrowl-slack-reporter.py
```

