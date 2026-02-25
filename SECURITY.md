# Security Policy

## Scope

This repository contains a cybersecurity lab simulation project.
It does **not** operate any production systems or hold real user data.

## Credential Safety

- All AWS Account IDs, IP addresses, and access key IDs shown in documentation
  are either AWS documentation examples or have been **decommissioned after the lab**.
- No real credentials, secrets, or PII are intentionally stored in this repository.
- If you discover a real credential accidentally committed, please report it immediately.

## Reporting a Vulnerability

If you find a real secret or sensitive value accidentally committed to this repository:

1. **Do not open a public GitHub issue.**
2. Contact the author directly via GitHub: [@Helmeyru](https://github.com/Helmeyru)
3. Include the file path and line number (not the credential value itself).

The author will rotate the affected credential immediately and remove it from git history.

## Disclaimer

This project is for **educational purposes only**.
All attack simulations were performed in an isolated AWS account owned by the author.
