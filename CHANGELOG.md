CHANGELOG
=========

Patrowl Slack Reporter
-----

1.3.2
-----

2019/12/09

### Bug fix

  - Fix warnings missing check


1.3.1
-----

2019/12/05

### Bug fix

  - Fix timezone issue

1.3.0
-----

2019/11/28

### Features

  - Add get_recent_assets_severity
  - AWS lambda support  


1.2.0
-----

2019/10/28

### Features

  - Report VT findings higher than LOW


1.1.0
-----

2019/10/23

### Features

  - Add logging engine
  - Add more whois pattern
  - increase retry to 39, 13mn

### Bug Fixes

  - ignore case for whois keys
  - if one scan is not finished, it doesn't block the report anymore
  - add dateutil in requirements.txt


1.0.1
-----

2019/10/11

### Bug Fixes

  - fix empty links list
  - increase scan status retry


1.0.0
-----

2019/10/10

### Features

  - First release
