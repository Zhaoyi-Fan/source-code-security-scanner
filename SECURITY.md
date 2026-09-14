# Security policy

## Supported versions

Security fixes are applied to the latest release line. Older tags are retained for project
history and should not be assumed to receive fixes.

| Version | Security fixes |
|---|---|
| Latest release | Yes |
| Earlier releases | No |

## Reporting a vulnerability

Please use GitHub's **Report a vulnerability** private-reporting form when it is available for
this repository. If private reporting is unavailable, open a minimal issue asking for a private
contact channel. Do not include a working exploit, real secret, private source code, or sensitive
target information in a public issue.

Useful reports identify the affected version, operating system and Python version, the security
boundary crossed, and a minimal synthetic reproduction. Examples include secret leakage despite
default redaction, escaping the requested scan root, unsafe report-file handling, or a malformed
input that changes an authoritative CI result into a false success.

This project analyses files as untrusted text and does not intentionally execute target source.
Please test only with code and systems you own or are authorized to assess.

## Scanner findings are not vulnerability reports

A scanner match is a review candidate, not proof that another project is vulnerable. Validate
reachability, data flow, controls, and intended behavior before contacting a maintainer. See the
[assurance model](docs/accuracy-and-assurance.md) for interpretation guidance.
