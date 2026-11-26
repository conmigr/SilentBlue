# Coverage ledger

Each in-scope file has one row. A source file lists the control families the detectors checked. A manifest or workflow lists `supply-chain`. Any other file has the reason `outside a language pack`. A file the walk could not read has `unreadable`. A file over the size limit has `too-large`.

`saturated` is true when every row has families or a reason, and no review path is unread. An assess budget stop lists those paths in `unread` and leaves the ledger unsaturated.
