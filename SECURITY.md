# Security Policy

## Reporting a Vulnerability

Please report suspected vulnerabilities privately through [GitHub Security Advisories](https://github.com/floegence/flowersec/security/advisories/new) or by email to [tangjianyin@gmail.com](mailto:tangjianyin@gmail.com).

Do not disclose vulnerabilities or real credentials, tokens, pre-shared keys, tickets, private keys, or other secrets in public issues, discussions, logs, screenshots, or examples. Include only the minimum information needed to reproduce and assess the issue. We will acknowledge the report and coordinate remediation and disclosure through the private channel.

## Supported Versions

Security fixes are provided for the latest released minor series. Users should upgrade to the latest patch release in that series before reporting an issue that may already be fixed.

## Sensitive Data in Memory

Flowersec performs best-effort cleanup of selected decoded secrets and active record-key buffers when their lifetime ends. This reduces how long sensitive values remain reachable, but it is not a guarantee of secure erasure: runtimes, garbage collectors, copy-on-write storage, cryptographic libraries, compiler optimizations, and the operating system may retain other copies.
