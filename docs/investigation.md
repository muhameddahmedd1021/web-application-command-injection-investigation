# Investigation

## Starting question

A WAF warning describes a suspicious request. Did the request only reach the WAF, or did the server execute it and make an outbound request?

DVWA's low-security command injection page passes the supplied value into a shell command used to run ping. Appending another command changes what the server executes. This investigation used only local ping, identity output and a harmless internal text download.

## Timeline

All times are UTC on 28 October 2026. Apache timestamps represent request start; the WAF audit timestamps in this run are recorded near transaction completion. A ping request takes approximately three seconds. Correlate identifiers and process relationships rather than expecting identical timestamps.

| Time | Observation |
| --- | --- |
| 22:50:37.108 | Normal POST reached Apache PID 13058; shell 13608 started ping 13609. WAF recorded 200 at 22:50:40.234. |
| 22:52:47 | Scheduled alert saved before command injection tests. |
| 22:52:51.078 | Short `id` input reached Apache. Shell 14325 started id 14332 as euid 33; there was no RCE warning. |
| 22:53:46.414 | Full-path identity command executed and matched 932160. Its WAF record contained an invalid UTF-8 byte from a compressed response. Retained as a calibration record. |
| 22:55:35.432 | After requesting an uncompressed upstream response, the same full-path identity test produced a valid audit record. Apache 14917 → shell 15280 → id 15283. |
| 22:55:48.674 | Download request reached Apache PID 15305; shell 15312 started ping, id and curl. |
| 22:55:51.784 | curl PID 15322 executed as euid 33 with the explicit proxy and internal URL in its native arguments. |
| 22:55:51.825 | Squid recorded one GET, TCP_MISS/200, to the text service. |
| 22:55:51.832479 | The file service logged the corresponding GET from 192.168.144.20. |
| 22:56:00 | The scheduled alert fired with two valid results: identity execution and download. |
| 22:56:51 | Downloaded file preserved; application target checked absent; WAF switched to On. |
| 22:57:00.657951 | Identical download POST blocked with 403. |
| 22:58:19.446040 | End of negative observation window: no new backend POST, www-data exec, proxy request or downloaded target. Origin log still contained one GET. |
| 22:58:35.898 | Normal ping POST reached Apache 15707; shell 16056 started ping 16057. WAF recorded 200 with engine ENABLED. |

## Allowed download: the evidence chain

1. WAF transaction `auJ9dNiFW_n_Ji-Anla9kwAAAAA` contains the URL-encoded input, client 192.168.144.1, target .20:8080, HTTP 200 and DETECTION_ONLY.
2. Apache's backend event carries the same value in `forwarded_request_id`. The front proxy generates and overwrites that header, rather than trusting a client-supplied identifier. The backend worker was PID 15305.
3. Native audit event 1166 records shell PID 15312 with PPID 15305 and the injected command. Events 1167–1169 record its ping, id and curl children. curl PID 15322 has PPID 15312 and euid 33 (`www-data`).
4. curl's recorded arguments specify the proxy `.20:3128`, force source .20 and request `http://192.168.144.1:8090/training-note.txt`. Squid independently records the GET and destination. The outbound client is the server, whereas the inbound WAF client was the browser.
5. The text service records one successful request. The saved 85-byte file matches the source SHA-256. Squid's 355 response bytes include HTTP headers and must not be described as the file size.

The proxy event has no process identifier. Its connection to curl rests on the exact URL, source, narrow time window, command arguments, independent origin request and matching file. It is not a direct proxy-to-PID join.

## Prevention comparison

The allowed and blocked request bodies are byte-identical. The blocked transaction is `auJ9vAu4EmFW7RLbUz-8ugAAAAA`, with engine ENABLED and status 403. It has no corresponding backend POST. The negative observation lasts 78.788 seconds after the blocked transaction; the recorded checkpoint starts slightly before it.

No new execution or outbound request appears in the monitored sources during that window. The download target was absent before and after the request. The original downloaded file had been moved into the evidence directory before the comparison. The subsequent successful normal ping is a control against a generally unavailable application.

This supports prevention of **this tested input in this window**. It does not prove the application is free of command injection or that every variant will be blocked.

## Conclusion and response

The allowed request caused server-side command execution and one internal file download. HTTP 200 alone would not establish that conclusion; process, proxy, origin and file evidence do. A WAF rule match alone would establish only detection of an attempt.

Enabling WAF blocking prevented the comparable request in the observed test. That was the response action performed. Fixing the underlying application remains a recommendation: validate the address, avoid passing untrusted input to a shell, and use a safe process/API interface. Restrict outbound access and retain both application and process monitoring. These recommendations were not implemented or tested as an application patch in this project.
