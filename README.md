# Dredd : Automated Detection Rule Analysis

Dredd primarily supports the process of evaluating [Sigma](https://github.com/Neo23x0/sigma) against [Mordor](https://github.com/hunters-forge/mordor) datasets.

Dredd also supports the evaluation of IDS rules against packet captures.

See the release blog post and video for more information: https://sra.io/blog/automated-detection-rule-analysis-with-dredd/ & https://youtu.be/FUxcKR-HaOM

## Supported Backends

Currently, Dredd supports the following Sigma backend/configs (though extending it isn't terribly difficult):

- Elasticsearch DSL + Winlogbeat

For PCAP analysis, Dredd supports the following IDS backends:

- Suricata

## Command-line Usage

### Elasticsearch

```
Usage: dredd-cli es [OPTIONS]

Options:
  -r, --rules TEXT             directory of rules  [required]
  -f, --format [custom|sigma]  rule format (default=sigma)
  -a, --archives TEXT          directory of Mordor archives  [required]
  -m, --merge                  evaluate rules against merged archives vs
                               individually
  -i, --ignore-exit-code       ignore the exit code and exit 0
  --help                       Show this message and exit.
```

**Merged Logs**

Ingests all mordor data at once then evaluates each rule against the merged data

```
dredd-cli es -r /path/to/sigma/rules -a /path/to/mordor/data -m
```


Example output

```
{
    "skipped": [],
    "unsupported": [],
    "all": {
        "results": {
            "sigma/win_mmc20_lateral_movement.yml[0]": 0,
            "sigma/schtasks.yml[0]": 1
        },
        "errors": []
    }
}
```

**Unmerged Logs**

Ingests all mordor data at once then evaluates each rule against each dataset

```
dredd-cli es -r /path/to/sigma/rules -a /path/to/mordor/data
```


Example output

```
{
    "skipped": [],
    "unsupported": [],
    "mordor/covenant_dcsync_all.tar.gz": {
        "results": {
            "sigma/win_mmc20_lateral_movement.yml[0]": 0,
            "sigma/schtasks.yml[0]": 0
        },
        "errors": []
    },
    "mordor/empire_userland_schtasks.tar.gz": {
        "results": {
            "sigma/win_mmc20_lateral_movement.yml[0]": 0,
            "sigma/schtasks.yml[0]": 1
        },
        "errors": []
    }
}
```

**Custom Rule**

Use an Elasticsearch DSL query against mordor data. 
See below for custom rule format

```
dredd-cli es -r /path/to/custom/rules -f custom -a /path/to/mordor/data -m
```


Example output

```
{
    "skipped": [
        "Word + cmd",
        "Word + PowerShell"
    ],
    "unsupported": [],
    "all": {
        "results": {
            "Scheduled Task[0]": 1
        },
        "errors": []
    }
}
```

**Note: Output**

In Dredd output, rules have "\[#\]" appended to the rule path/name. 
This is primarily included to support Sigma rules with multiple detections since these translate to multiple queries. 
The number within the brackets indicate the query number within the rule (starting with 0).

**Note: Skipped/Unsupported**

Skipped and unsupported are both top-level keys in the results dict. 
Skipped rules are rules that are in-compatible with the backend. For example: supplying a Splunk rule to an ES backed).
Unsupported rules are rules that use features not supported by the backend. For example: using "near" with an Elasticsearch backend.

**Note: Log archives**

This tool assumes imported log data is from a trusted source. Do not process untrusted data.

### Suricata

```
Usage: dredd-cli suricata [OPTIONS]

Options:
  -r, --rules TEXT  directory of rules  [required]
  -p, --pcaps TEXT  directory of PCAPs  [required]
  -m, --merge       evaluate rules against merged archives vs individually
  --help            Show this message and exit.
```

**Merged Logs**

Merges all rule files together then evaluates against all PCAPs at once

```
dredd-cli suricata -r /path/to/ids/rules -p /path/to/pcaps -m
```

Example output

```
{
    "all": {
        "ET NETBIOS DCERPC SVCCTL - Remote Service Control Manager Access": 10,
        "ET POLICY PsExec service created": 58,
        "ET USER_AGENTS WinRM User Agent Detected - Possible Lateral Movement": 73
    }
}
```

**Unmerged Logs**

Merges all rule files together then evaluates against each PCAP individually

```
dredd-cli suricata -r /path/to/ids/rules -p /path/to/pcaps
```

Example output

```
{
    "/home/ubuntu/pcaps/all/cap1.pcap": {
        "ET NETBIOS DCERPC SVCCTL - Remote Service Control Manager Access": 4,
        "ET USER_AGENTS WinRM User Agent Detected - Possible Lateral Movement": 16
    },
    "/home/ubuntu/pcaps/all/cap2.cap": {
        "ET POLICY WinRM wsman Access - Possible Lateral Movement": 26,
        "ET USER_AGENTS WinRM User Agent Detected - Possible Lateral Movement": 26
    }
}
```

**Note: Suricata container**

Suricata rule analysis uses a custom container. 
The Dockerfile can be found [here](dockerfiles/suricata.dockerfile).
The Docker Hub page can be found [here](https://hub.docker.com/r/securityriskadvisors/suricata).

## Custom Rules (Sigma only)

Custom rules allow for the use of platform specific formats such as Splunk SPL and Elasticsearch DSL directly.

The format for this is extremely simple YAML. There are three required fields:

- name (string): rule name
- backend (string): backend name (e.g "elasticsearch")
- rule (string): the rule content

You can also provide an optional dictionary of metadata as a field.

**Example Splunk custom rule**

```
---
name: My rule
backend: splunk
metadata:
  foo: bar
rule: |
  (index="windows" ParentImage="*\\winword.exe" Image="*\\cmd.exe")
```

These rules are used directly and not translated to different platforms.
For example, if your custom rules include a Splunk query but Elasticsearch is in use, the rule will be skipped.
Elasticsearch is currently the only supported Dredd backend so only Elasticsearch DSL custom rules will be processed

## Exit Codes (Sigma only)

By default, Dredd will exit with an exit code of 1 if any of the rules have 0 hits against the logs.
This can be ignored by specifying the "-i" option. "-i" will cause Dredd to always exit 0 (save for exceptions).

## Installation

**Pre-requisites**

- Python3 (virtualenv recommended)
- Docker

**Steps**

```
pip install -r requirements.txt
```

## To-dos 

- fine-grained analysis configurations

## Changelog

**8/25/2020**
 
- initial commit
