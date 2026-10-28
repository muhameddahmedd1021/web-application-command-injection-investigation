# Evidence provenance and limits

## Sources

| Evidence | Producer and meaning |
| --- | --- |
| `waf-audit.jsonl` | Native ModSecurity JSON audit records, with the one invalid-encoding calibration line preserved separately. |
| `waf-access.jsonl`, `backend-access.jsonl` | Apache CustomLog output. Includes worker PID and front-generated request identifier. |
| `process-audit.jsonl` | A small collector groups native auditd SYSCALL/EXECVE records. Original `raw_records`, timestamp and audit serial remain in every event; PID, PPID, euid and argv are decoded from them. `command` is a readable rendering of argv. |
| `proxy-access.jsonl`, `access.log` | Squid's native custom JSON format and default access format for the same request. |
| `origin-access.jsonl` | The harmless file service's request log. Corroborating evidence outside the Splunk index. |
| `allowed-download.txt`, `download-proof.json` | Preserved file bytes, SHA-256, original namespace path, ownership and preservation details. |
| `before-blocked.json`, `after-blocked.json` | Read-only filesystem/log checks around the blocked comparison. They are observations, not additional attack events. |

The audit collector does not send requests or execute the cases. All form inputs were submitted individually through the browser. The configurations and helper source are included for reproducibility.

Apache uses systemd `PrivateTmp=yes`. The application wrote `/tmp/soc-training-note.txt` inside Apache's temporary namespace; the host-visible location is recorded in download-proof.json. Checking only the host's ordinary `/tmp` would incorrectly suggest the download was absent.

## Preserved encoding gap

The fourth original WAF audit line, for transaction `auJ8-gY5EIcAEr-n95eyowAAAAU`, contains an invalid UTF-8 byte in a compressed response body. It is preserved byte-for-byte as `calibration-waf-row-4.bin`, not repaired or relabeled as a successful JSON record. `waf-export-notes.json` records the original complete audit file's hash and identifies the excluded line. The JSONL export contains the other eight original lines unchanged.

The proxy was then configured to remove Accept-Encoding from the upstream request. The later identity and download tests produced valid native JSON. The invalid row is excluded from JSON-based evidence correlation; its independent Apache and auditd records remain available. Splunk's seven-POST overview includes the earlier partial record and displays a blank mode for it.

## Integrity and scope

The evidence hash manifest covers the exported evidence files. Screenshots are original browser captures without compositing, rewritten values or annotations. Request cookies, Authorization and Set-Cookie were masked by ModSecurity at log generation; login request bodies were outside the command-page audit scope.

The process rule monitors successful and failed execve attempts with effective UID 33 on x86-64. It is not a complete endpoint sensor: it does not prove absence of shell built-ins, other users, other architectures, delayed activity outside the observation window or unmonitored network paths. The blocked result combines this bounded coverage with backend, proxy, file and origin checks.

The short `id` test demonstrates a real rule-coverage gap. The project does not claim a WAF warning for that input. The full-path identity and download requests did trigger command-execution rules, while DetectionOnly allowed them to continue.

The single VM deployment provides observable service roles, not host isolation between them. Logs and settings show a controlled training environment, not a production hardening assessment. Existing Splunk historical data is outside the new `soc_web` index and this investigation.
