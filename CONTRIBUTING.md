# Contributing

Install with `python -m pip install -e .`, then run `python -m unittest discover -s tests -v`. Add a synthetic regression fixture for behavior changes. Keep runtime dependencies at zero unless there is a clear reviewed reason to add one.

Never weaken isolated-destination, path-validation, streamed-size or error-redaction guarantees without documenting the changed threat model. Do not add `extractall`, automatic source-location restores, shell execution, telemetry or upload behavior. Test both ZIP and supported TAR forms when changing archive handling. Keep examples fictional and exclude secrets, real backups, generated reports and personal author information.
