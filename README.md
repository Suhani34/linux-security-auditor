# Linux Security Auditor

A modular Bash-based Linux security auditing tool that evaluates important host security configurations, identifies potential weaknesses, generates human-readable and JSON reports, compares audits historically, and supports automated scheduled execution.


## Project Purpose

Linux systems contain many security-sensitive configurations involving users, privileges, authentication, services, storage, networking, updates, and firewall rules.

Manually checking these settings can be repetitive and error-prone.

Linux Security Auditor automates these checks and presents the results using severity-based findings so that administrators or security analysts can quickly identify areas that may require investigation.


## Features

- Modular Bash architecture
- System information collection
- User and account security auditing
- Sudo and privilege security auditing
- Authentication log analysis
- SSH security checks
- Service and process inspection
- Network-related security checks
- Firewall security auditing
- Disk and filesystem security checks
- Security update checks
- Severity-based findings
- Human-readable reports
- JSON machine-readable reports
- Historical audit comparison
- Automated execution using cron or systemd
- Timestamped report storage
- Report retention/cleanup support
- Required and optional dependency detection
- Root and non-root execution handling
- Defensive error handling
- Meaningful process exit codes


## Finding Severity Levels

Audit results are categorized by severity:

| Level | Meaning |
|---|---|
| `PASS` | The checked configuration passed the security condition. |
| `INFO` | Informational system or security-related information. |
| `WARNING` | A configuration may require review or hardening. |
| `CRITICAL` | A potentially serious security issue was detected. |


## Security Checks

The auditor evaluates several areas of Linux host security.

### System Information

Collects basic information about the host and operating environment to provide context for the audit.

### User & Account Security

Reviews local user/account configuration and identifies potentially security-sensitive account conditions.

### Sudo & Privilege Security

Reviews privilege-related configuration and sudo access where sufficient permissions are available.

### Authentication Security

Analyzes authentication-related information and logs where supported and accessible.

### SSH Security

Reviews SSH-related configuration and service information when SSH is installed and detectable.

### Services & Processes

Examines running services/process-related security information using commands available on the host.

### Network Security

Evaluates applicable network-related information using available operating-system utilities.

### Firewall Security

Detects and evaluates supported firewall information, including UFW where available.

### Disk & Filesystem Security

Reviews storage and filesystem-related security conditions and permissions.

### Security Updates

Checks applicable package/update information when supported package-management commands are available.


## Project Architecture

The project follows a modular architecture in which `auditor.sh` acts as the main controller and individual security areas are implemented in separate modules.

```text
linux-security-auditor/
├── auditor.sh
├── lib/
│   ├── common.sh
│   ├── system_checks.sh
│   ├── user_checks.sh
│   ├── ssh_checks.sh
│   ├── network_checks.sh
│   ├── service_checks.sh
│   ├── filesystem_checks.sh
│   ├── auth_checks.sh
│   ├── update_checks.sh
│   └── reporting.sh
├── reports/
├── logs/
├── scripts/
│   ├── run-audit.sh
│   └── cleanup-reports.sh
└── schedules/
    ├── cron/
    │   └── run-auditor-cron.sh
    └── systemd/
        ├── linux-security-auditor.service
        └── linux-security-auditor.timer


```markdown
### Core Components

| File | Purpose |
|---|---|
| `auditor.sh` | Main entry point and audit orchestrator. |
| `lib/common.sh` | Shared helper functions and dependency handling. |
| `lib/system_checks.sh` | System-related security checks. |
| `lib/user_checks.sh` | User/account security checks. |
| `lib/ssh_checks.sh` | SSH-related checks. |
| `lib/network_checks.sh` | Network-related checks. |
| `lib/service_checks.sh` | Service/process-related checks. |
| `lib/filesystem_checks.sh` | Disk and filesystem security checks. |
| `lib/auth_checks.sh` | Authentication-related checks. |
| `lib/update_checks.sh` | Security/update-related checks. |
| `lib/reporting.sh` | Report creation, findings, summaries, and reporting functionality. |
| `scripts/run-audit.sh` | Wrapper used for automated audit execution. |
| `scripts/cleanup-reports.sh` | Removes old reports according to the configured retention policy. |
| `schedules/cron/run-auditor-cron.sh` | Cron-compatible audit execution wrapper. |
| `linux-security-auditor.service` | systemd service definition for running an audit. |
| `linux-security-auditor.timer` | systemd timer definition for scheduled audits. |


## How It Works

At a high level, the auditor performs the following workflow:

1. Determines the project location.
2. Loads the required Bash modules.
3. Initializes runtime variables and finding counters.
4. Validates required dependencies.
5. Initializes report files.
6. Reports optional dependency availability.
7. Executes each security check module.
8. Records findings and severity levels.
9. Generates the audit summary.
10. Creates human-readable and machine-readable reports.
11. Performs historical comparison when previous audit data is available.
12. Returns an appropriate process exit status.


## Installation

Clone the repository:

```bash
git clone <https://github.com/Suhani34/linux-security-auditor>

cd linux-security-auditor
chmod +x auditor.sh


## Dependencies

The auditor checks dependencies before performing the audit.

### Required Dependencies
Core commands required for normal operation include standard Linux utilities such as:

awk
grep
sed
cut
sort
uniq
tr
wc
head
find
stat
df
date
hostname
uname
uptime
whoami
id
getent
tee
mkdir
touch
chmod
mv
rm


## Optional Dependencies

sudo
systemctl
journalctl
ufw
ss
ps
apt
apt-get


## Root vs Non-Root Execution

The auditor is designed to work safely in both privileged and non-privileged environments.

Running:

```bash
./auditor.sh


## Reports

Audit results are stored in the project's report directory.

```text
reports/


## Historical Audit Comparison

The auditor can compare the current audit against previous audit data.

Historical comparison helps identify security changes over time, such as:

- newly introduced warnings
- newly introduced critical findings
- resolved findings
- changes in the overall security posture

This makes the auditor useful not only for one-time inspection but also for tracking security configuration changes over time.


## Testing and Validation

The project is validated using several levels of testing.

### Bash Syntax Validation

The main script can be checked using:

```bash
bash -n auditor.sh


## Exit Codes

The auditor uses process exit codes to make failures easier to identify and automate.

| Exit Code | Meaning |
|---:|---|
| `0` | Audit completed successfully. |
| `1` | Runtime or report initialization error. |
| `2` | Required dependency is unavailable. |

Exit codes are useful when the auditor is executed through cron, systemd, CI/CD pipelines, or other automation systems.


## Example Output

============================================
        Linux Security Auditor
============================================

[INFO] Starting security audit...

--- System Information ---
...

--- User & Account Security ---
...

--- Firewall Security ---
...

--- Disk & Storage Security ---
...

============================================
             Audit Summary
============================================
PASS     : ...
INFO     : ...
WARNING  : ...
CRITICAL : ...


## Limitations

- The auditor primarily targets Linux environments and has been developed/tested on Ubuntu.
- Some checks depend on distribution-specific utilities.
- Certain security checks require root privileges.
- Some checks may be skipped when optional commands are unavailable.
- Availability of `systemctl` and `journalctl` depends on the target system and init/logging configuration.
- UFW-specific firewall checks require UFW to be installed.
- Package/update checks may depend on APT-based package management.
- The tool performs host security auditing and does not replace a complete vulnerability scanner, EDR, SIEM, IDS/IPS, or professional security assessment.
- Results should be reviewed by an administrator or security professional rather than treated as automatic proof that a host is secure.


## Security Considerations

The auditor is designed primarily for inspection and reporting.

Running with elevated privileges provides access to additional security information, so users should review the source code before executing the project with `sudo`.

Generated reports may contain system/security information and should therefore be stored with appropriate permissions and access controls.


## Future Improvements

Possible future enhancements include:

- support for additional Linux distributions
- additional firewall implementations
- broader SSH configuration analysis
- configurable security policies
- external configuration files
- enhanced JSON schemas
- HTML reporting
- integration with SIEM or monitoring platforms
- mapping checks to security hardening standards such as CIS guidance
- expanded automated test coverage


## Project Learning Outcomes

This project demonstrates practical experience with:

- Linux administration
- Bash scripting
- Linux permissions
- users and groups
- sudo and privilege concepts
- authentication logging
- SSH security
- systemd
- cron
- firewall inspection
- filesystem security
- Linux package updates
- modular shell scripting
- error handling
- dependency management
- machine-readable JSON output
- scheduled automation
- Git and GitHub


## License

This project is intended for educational and defensive security auditing purposes.
