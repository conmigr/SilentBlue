# Triage record

Dispositions live under the state directory in `triage/<repo-hash>.json`, next to threat-model acceptance. Each entry has `case_id`, `disposition` (`open`, `assigned`, or `accepted`), `owner`, `reason`, `expires`, and `recorded_at`. Accepted requires `expires` as `YYYY-MM-DD`.

A test-secret confirm lives in `confirm/<repo-hash>.json`. Each entry has `case_id`, `path`, `rule_id`, `line_hash`, `reason`, and `recorded_at`. The line is not stored. The repository is not a place either file can be written.

Nothing writes these files during a scan. `/triage` only lists what an operator has already stored.
