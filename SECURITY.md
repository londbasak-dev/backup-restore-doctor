# Security scope

This MVP checks bounded archive structure and restore readability. It does not establish that contents are harmless, a backup is complete, or applications will recover. Use only archives you are authorized to inspect. Restore only into a new disposable directory under a trusted parent. Never point a drill at a production restore location.

Do not add production backups, keys, cookies, tokens, environment files, reports or restored private files to this repository. Reports intentionally contain counts and fixed codes, not member names or contents. CLI arguments can still be recorded by your shell or operating system; avoid embedding secrets in them.

For a suspected defect, use a minimal synthetic reproducer. If a hosting provider offers private vulnerability reporting, use that private channel. No security contact or hosted repository has been configured by this template. Do not post exploitable private archives or sensitive logs in a public issue. Include Python/OS versions and the fixed error code without private paths or data.
