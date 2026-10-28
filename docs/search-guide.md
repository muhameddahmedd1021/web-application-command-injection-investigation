# Search guide

Each saved SPL file answers one question. Every search was run in Splunk's Search UI and compared with the native evidence. [UI-validation.json](../searches/UI-validation.json) records the actual job identifiers; [results](../searches/results/) preserves their exported rows.

The epoch bounds deliberately preserve this investigation's UTC windows. For a new run, replace them with that run's times. `earliest` is inclusive and `latest` is exclusive.

| Search | Question | Verified result |
| --- | --- | --- |
| [01](../searches/01-waf-decisions.spl) | What happened to each submitted input? | 7 POST rows, including the calibration inputs; one 403. |
| [02](../searches/02-backend-requests.spl) | Which requests reached the backend worker? | 6 POST rows; blocked request ID absent. |
| [03](../searches/03-download-processes.spl) | What processes ran during the download? | 4 rows: shell, ping, id, curl; same parent chain. |
| [04](../searches/04-proxy-download.spl) | Did the server fetch the internal URL through the proxy? | 1 GET, 200, TCP_MISS, source .20. |
| [05](../searches/05-blocked-window.spl) | Were backend POSTs, process executions or proxy requests observed during the blocked window? | One statistics row containing count=0. |
| [06](../searches/06-rce-warnings.spl) | Which later requests produced RCE warnings? | 3 rows: full-path id, allowed download, blocked repeat. |

`table` chooses the fields to display; it does not infer compromise. `stats count` returns a statistics row even when zero events match. The Boolean expression in search 05 selects the three kinds of side effects being checked; ordinary backend OPTIONS traffic is outside that question.

The WAF JSON contains nested fields. `spath path=audit_data.engine_mode output=mode` explicitly reads the engine value. Some automatically extracted fields were blank in the original alert result, so engine mode was checked against the native audit record and the explicit-path search. The earlier invalid compressed calibration row still has no parsed mode; do not fill it with an assumed value.

Search the WAF's actual `audit_data.messages{}` field for `attack-rce`. Searching that word anywhere in the raw record also matches rule configuration metadata and returned the benign baseline during query preparation. That broad search was rejected before the alert was saved.

## Scheduled alert

The tested search, settings before validation and settings after stopping the schedule are preserved under [evidence](../evidence/). The alert ran every minute over the previous 15 minutes, fired when results were greater than zero, and recorded a Triggered Alerts entry with 900-second suppression. It had no external notification action.

Its actual scheduled job was `scheduler__mohamedahmed__search__RMD56017a17fbf3872ba_at_1793228160_4`. The [result export](../evidence/scheduled-alert-results.json) contains two rows and agrees with the [trigger screenshot](../images/07-scheduled-alert-trigger.jpg). A manual search match was not used as a substitute for this scheduled trigger.

The schedule is now stopped to avoid repeated lab alerts. The alert remains enabled so its trigger history is retained. Scheduling depends on a Splunk license that supports scheduled alerts.
