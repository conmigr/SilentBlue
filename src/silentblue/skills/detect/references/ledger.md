# Coverage ledger

Each in-scope file has one row. A source file lists the control families the detectors checked. A manifest or workflow lists `supply-chain`. Any other file has the reason `outside a language pack`. A file the walk could not read has `unreadable`. A file over the size limit has `too-large`.

`saturated` is the detector ledger. It is true when every row has families or a reason. Unread review paths do not change it.

An assess report also has a model ledger. `model_saturated` is true when every path on the review list was read. A path still waiting is `unread`. A path whose reply failed twice is `skipped`, with the reason on `model_state`. A budget stop leaves those paths unread and the title Partial. The next step is resume. The detector ledger can stay saturated on that same run.
