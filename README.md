[![Tests](https://github.com/lbausch/filebeat-fail2ban/actions/workflows/main.yml/badge.svg)](https://github.com/lbausch/filebeat-fail2ban/actions/workflows/main.yml)

# filebeat-fail2ban <!-- omit in toc -->
Fully tested Filebeat module to ingest Fail2Ban logs

- [Installation](#installation)
- [Configuration](#configuration)

## Installation
+ Copy `module/fail2ban` to `/usr/share/filebeat/module/`
+ Copy `modules.d/fail2ban.yml.disabled` to `/etc/filebeat/modules.d/fail2ban.yml`

## Configuration
All configuration is done in `/etc/filebeat/modules.d/fail2ban.yml`.

The module expects the Fail2Ban log in `/var/log/fail2ban.log`, it's possible to use custom paths for the log by specifying `var.paths`:

```yaml
# Module: fail2ban

- module: fail2ban
  # ban log
  main:
    enabled: true

    # Set custom paths for the log files. If left empty,
    # Filebeat will choose the paths depending on your OS.
    var.paths:
      - /var/log/fail2ban/ban.log
```
