# Cloud-Security-Scanner

A cloud security scanner written in Python, built around a generic, provider-independent
core and extensible through plugins. The goal is not to replicate ready-made tools like
Prowler or ScoutSuite, but to design a clean software architecture from scratch, applied to
a real problem: enumerating the resources of a cloud account, detecting the most common
misconfigurations, and producing a structured report.

The same core works on both **AWS** and **Azure**: only the provider and the loaded plugins
change.

Developed as a project work for the Cybersecurity course (ITS Umbria Academy).

---

## Core idea

Most cloud incidents are not caused by platform bugs, but by **misconfigurations** on the
user's side (buckets left public, overly broad IAM permissions, ports open to everyone,
unencrypted data). This tool looks for exactly those misconfigurations.

## Architecture

The core does not know what AWS or Azure is: it only knows how to load a list of plugins and
call their `run()` method, receiving standard `Finding` objects in return (severity,
resource, description, remediation). Each plugin uses the provider's SDK (`boto3` for AWS,
`azure-sdk` for Azure), while the Provider abstracts authentication and the common API calls.

| Component | Role |
|---|---|
| `core/engine.py` | Dynamically loads the plugins from a folder and runs them |
| `core/finding.py` | Standard class for results (severity, resource, description, remediation) |
| `core/plugin.py` | Abstract interface common to all plugins |
| `core/report.py` | Terminal table output and JSON report saving |
| `providers/base.py` | Abstract interface common to all cloud providers |
| `providers/aws_provider.py` | AWS authentication and API calls (boto3) |
| `providers/azure_provider.py` | Azure authentication and API calls |
| `plugins/aws/*.py` | AWS-specific checks |
| `plugins/azure/*.py` | Azure-specific checks |

Plugins are discovered automatically: just add a file to the `plugins/<provider>/` folder with
a class that inherits from `Plugin`. No registration needed anywhere.

## Implemented checks (AWS)

| Plugin | What it detects | Severity |
|---|---|---|
| `public_storage.py` | Publicly exposed S3 buckets | HIGH |
| `iam_overprivileged.py` | IAM users with overly powerful policies (AdministratorAccess, PowerUserAccess, IAMFullAccess) | HIGH / CRITICAL |
| `open_network.py` | Security Groups with Ingress rules open to `0.0.0.0/0` (SSH, RDP, DB...) | MEDIUM / HIGH / CRITICAL |
| `encryption_at_rest.py` | S3 buckets and EBS volumes without encryption at rest | MEDIUM / HIGH |
| `imds_check.py` | EC2 instances that still allow IMDSv1 (exposed to SSRF) | HIGH |
| `cloudtrail_audit.py` | CloudTrail missing, disabled, or without multi-region coverage | MEDIUM / HIGH |

## Implemented checks (Azure)

Same core, Azure services. Each check has a direct AWS counterpart.

| Plugin | What it detects | AWS counterpart | Severity |
|---|---|---|---|
| `public_storage.py` | Storage accounts with public blob access | Public S3 buckets | HIGH |
| `iam_overprivileged.py` | Owner / Contributor roles on overly broad scopes (Subscription / Resource Group) | IAM overprivileged | HIGH / CRITICAL |
| `open_network.py` | Network Security Groups (NSG) with Inbound rules open to the Internet (`*`, `0.0.0.0/0`) on critical ports | Open Security Groups | MEDIUM / HIGH / CRITICAL |
| `encryption_at_rest.py` | Storage accounts and managed disks not using customer-managed keys (CMK) | Encryption at rest | MEDIUM |
| `imds_check.py` | VMs without Metadata Security Protocol in *Enforce* mode on the IMDS | IMDSv2 | MEDIUM / HIGH |
| `activity_log_audit.py` | Subscription Activity Log not exported or missing security categories | CloudTrail | MEDIUM / HIGH |

> Note: on Azure, encryption at rest is always enabled by default (Microsoft-managed keys);
> the check flags resources that do not use customer-managed keys (CMK), as required by CIS
> baselines for critical data.

## Requirements

- Python 3.12 (see `.python-version`)
- The dependencies in `requirements.txt` (`boto3` for AWS, the Azure SDKs, `flask` for the web UI)
- AWS CLI and/or Azure CLI configured with a valid profile

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage (CLI)

The scanner reads credentials from the active cloud profile (it does not manage them itself).

### AWS

```bash
export AWS_PROFILE=<your-profile>
export AWS_DEFAULT_REGION=eu-central-1
python main.py --provider aws
```

### Azure

```bash
az login
python main.py --provider azure
```

At the end, a summary table is printed to the terminal and a `report.json` is saved with all
the details and remediations.

### Example output

```
================================================================================
SEVERITY   | RESOURCE                       | DESCRIPTION
================================================================================
MEDIUM     | EBS Default Encryption (eu-central-1) | EBS default encryption is NOT en...
HIGH       | EBS Volume: vol-0abc1234def567890 (eu-central-1) | EBS volume 'vol-0abc...
CRITICAL   | IAM User: dev-example          | Risky attached policy: 'Administr...
HIGH       | EC2 Instance: i-0abc1234def567890 | The instance still allows IMDSv1...
HIGH       | example-sg (sg-0abc1234def567890) | Ingress rule open to 0.0.0.0/0...
================================================================================

[*] Detailed report saved to report.json
```

## Web interface (local)

In addition to the CLI, a **local web interface** is available (`app.py` +
`templates/index.html`) that reuses the same `Engine`: an easier way to use the scanner,
without the terminal.

```bash
pip install -r requirements.txt
export AWS_PROFILE=<your-profile>        # for AWS; for Azure use 'az login'
python app.py
```

Then open **http://127.0.0.1:5050** in the browser: choose the provider (AWS / Azure), start
the scan, and the findings appear in a table colored by severity, with counts and a button to
download the JSON report.

- The server listens **only on `127.0.0.1` (localhost)**: it is not exposed on the network and
  uses the local profile's credentials, exactly like the CLI.
- Port **5050** and not 5000, because on macOS port 5000 is used by the AirPlay Receiver.

## Adding a new check

1. Create a file in `plugins/aws/` (or `plugins/azure/`), e.g. `my_check.py`.
2. Define a class that inherits from `Plugin` and implements `run(self, provider)`.
3. Use the provider's methods (or `provider.session.client(...)` for AWS) to read the
   resources, and return a list of `Finding` objects.

The engine will load it automatically on the next run.

## Notes on the test environment

The checks must be validated against a deliberately vulnerable environment. During the
project, the AWS part was tested against an environment prepared by the defensive team (blue
team), using a read-only identity (`SecurityAudit` / `ViewOnlyAccess`): the scanner enumerates
without being able to modify anything, and the activity is recorded by their CloudTrail. The
Azure part was tested on a personal test account.

## Disclaimer

This tool was built for **educational purposes** and must be run **only on cloud accounts you
own or for which you have explicit authorization**. Using it against third-party infrastructure
without permission is illegal. The authors assume no responsibility for improper use.

## License

Distributed under the MIT license. See the [LICENSE](LICENSE) file.
