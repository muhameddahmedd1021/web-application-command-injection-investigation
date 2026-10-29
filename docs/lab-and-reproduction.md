# Lab and manual reproduction

## Observed layout

| Role | Address / listener |
| --- | --- |
| Browser and harmless file service | Windows VMware host, 192.168.144.1; file service on 8090 |
| WAF | Linux VM 192.168.144.20:8080 |
| DVWA backend | Same VM, 127.0.0.1:8081; local access only |
| Squid | Same VM, 192.168.144.20:3128 |
| MariaDB | Same VM, 127.0.0.1:3306 |
| Splunk | Same VM, web 8000; dedicated index `soc_web` |

WAF, DVWA, Squid and Splunk are services on the same Linux VM. The Windows host runs the browser and internal text-file service.

Installed versions: Apache 2.4.58, PHP 8.3.6, MariaDB 10.11.14, ModSecurity 2.9.7, CRS 3.3.5, Squid 6.14 and auditd 3.1.2. DVWA source was the official repository at commit `a1978a2fed195acd093010af6395f86a281537ca`. Splunk was the existing 9.4.1 lab installation. Packages came from Ubuntu's repositories.

## Saved configuration

The published files describe the configuration used for this run:

| Component | File | Main setting |
| --- | --- | --- |
| WAF before blocking | [detection-only-vhost.conf](../configuration/detection-only-vhost.conf) | Front vhost uses `SecRuleEngine DetectionOnly`. |
| WAF after blocking | [soc-web-lab.conf](../configuration/soc-web-lab.conf) | Front vhost uses `SecRuleEngine On`; backend WAF stays Off. |
| Proxy | [squid.conf](../configuration/squid.conf) | Source .20 may reach .1:8090; other requests are denied. |
| Native processes | [audit rule](../configuration/soc-web-lab.rules) and [collector](../configuration/collect_web_audit.py) | Records execve with euid 33 and retains original audit records. |
| Splunk collection | [inputs.conf](../configuration/inputs.conf), [props.conf](../configuration/props.conf), [indexes.conf](../configuration/indexes.conf) | Five monitored log sources in `soc_web`. |

The saved [Search UI results](search-guide.md) show received WAF, backend, process and proxy events. The [download proof](../evidence/native/download-proof.json) and [preserved file](../evidence/native/allowed-download.txt) retain the file size, owner, path and SHA-256.

## Preparation

1. In an isolated lab, install Apache, PHP with mysqli, MariaDB, ModSecurity, the CRS package, Squid, auditd, curl and ping. Use the official DVWA installation instructions for its database and PHP configuration. Create dedicated local database credentials; the published configuration contains no database password.
2. Place DVWA under `/var/www/soc-dvwa`. Configure the backend and front vhosts using the included [Apache configuration](../configuration/). Enable `proxy`, `proxy_http`, `headers`, `unique_id` and `security2`. Load the package's CRS configuration. 
3. In the global ModSecurity configuration, use JSON audit output at `/opt/soc-web-lab/logs/waf-audit.jsonl`, with global rule/audit engines Off. The front vhost overrides the engine to DetectionOnly, and audits only `/vulnerabilities/exec/`; the backend keeps its engines Off to avoid applying the WAF twice. The included vhost contains the cookie/header masking actions, parts ABCFHKZ, front-generated request ID and reverse-proxy settings. The preserved `detection-only-vhost.conf` is the pre-blocking version; `soc-web-lab.conf` is the final On version.
4. Start in DetectionOnly mode. Keep DVWA's lab security level Low and sign in with the dedicated lab account. Use its setup page once to initialize the database. Protect configuration backup files from HTTP access, as the included FilesMatch setting does.
5. Use the included complete Squid configuration. It permits only source .20 to destination .1 on port 8090 and denies other requests. Caching is disabled. The custom JSON log and native default access log are both enabled.
6. Start [serve_training_file.py](../configuration/serve_training_file.py) with Python on the Windows host. It binds only .1:8090 and serves one 85-byte plain-text file. Permit inbound TCP to that listener only from .20. Check that the firewall does not have a conflicting application block; keep any exception limited to that lab port and source.
7. Load the included audit rule for x86-64 execve with euid 33 and key `soc_web_exec`. Run the collector as a service with read access to audit.log; it writes process-audit.jsonl. Its role is collection only. Preserve the native raw records and do not manufacture process events.
8. Install the included `indexes.conf`, `inputs.conf` and `props.conf` in a dedicated Splunk app directory. Restart Splunk to load them and confirm the new index receives WAF, front access, backend access and process records. Proxy records appear after a real proxy request. The existing lab Splunk process ran as root; a production deployment should use appropriate service users and log permissions rather than copying that privilege model.
9. Before submitting command inputs, create the scheduled alert from the Search UI using [the preserved tested settings](../evidence/alert-settings-before.json). Enable Add to Triggered Alerts. Do not configure email or webhook actions for these lab tests.

The proxy removes Accept-Encoding before forwarding upstream so that compressed response bytes do not corrupt a ModSecurity JSON response-body entry. Keep the independent native access and process sources even when one audit format has a problem.

## Configuration placement and activation

These commands describe the recorded Ubuntu setup. Run them inside an isolated lab with the same addresses and installed packages. Keep database credentials local to DVWA's configuration; no database password is included here.

### Apache listeners and vhosts

Place the published [ports.conf](../configuration/ports.conf) at `/etc/apache2/ports.conf`. It binds the WAF to `.20:8080` and the backend to loopback only:

```apache
Listen 192.168.144.20:8080
Listen 127.0.0.1:8081
```

Place `soc-web-resources.conf` in `/etc/apache2/conf-available/`. It defines the `socweb` log format used by both vhosts. Place `detection-only-vhost.conf` at `/etc/apache2/sites-available/soc-web-lab.conf` for the initial cases.

```bash
sudo a2dissite 000-default
sudo a2enmod proxy proxy_http headers unique_id security2
sudo a2enconf soc-web-resources
sudo a2ensite soc-web-lab
```

Use `/var/www/soc-dvwa` for the application and keep the installed CRS package's loader enabled through the security2 module. In `/etc/modsecurity/modsecurity.conf`, set the following directives, replacing existing values rather than creating duplicate audit outputs:

```apache
SecRuleEngine Off
SecAuditEngine Off
SecAuditLogFormat JSON
SecAuditLog /opt/soc-web-lab/logs/waf-audit.jsonl
```

The front vhost overrides the global engine to DetectionOnly and enables auditing for the command page. The backend remains Off so it does not apply the WAF twice. `RequestHeader unset Accept-Encoding` requests an uncompressed upstream response. Cookie and authorization headers are masked by the included rules.

Create `/opt/soc-web-lab/logs` and `/opt/soc-web-lab/evidence` with the permissions described below. Then check configuration and reload Apache:

```bash
sudo apachectl configtest
sudo systemctl reload apache2
```

For the blocking comparison, replace the same enabled site's contents with the published final `soc-web-lab.conf`, run `configtest` again and reload. Only the front `SecRuleEngine` changes from DetectionOnly to On between the two published vhost files.

### Proxy

Install the complete published `squid.conf` as `/etc/squid/squid.conf` so the lab ACL is evaluated before a final deny. It disables caching and writes both native Squid and custom JSON logs.

```bash
sudo squid -k parse
sudo systemctl restart squid
```

### Process collection

The recorded setup uses local administrative access to install the audit collector. The collector reads auditd records; it does not submit the web-form inputs.

```bash
sudo install -d -m 0750 -o root -g labadmin /opt/soc-web-lab /opt/soc-web-lab/logs /opt/soc-web-lab/evidence
sudo install -m 0755 collect_web_audit.py /opt/soc-web-lab/collect_web_audit.py
sudo install -m 0640 soc-web-lab.rules /etc/audit/rules.d/soc-web-lab.rules
sudo auditctl -a always,exit -F arch=b64 -S execve -F euid=33 -k soc_web_exec
sudo touch /opt/soc-web-lab/logs/process-audit.jsonl
sudo chown root:labadmin /opt/soc-web-lab/logs/process-audit.jsonl
sudo chmod 0640 /opt/soc-web-lab/logs/process-audit.jsonl
sudo install -m 0644 soc-web-audit.service /etc/systemd/system/soc-web-audit.service
sudo systemctl daemon-reload
sudo systemctl start soc-web-audit
sudo systemctl is-active soc-web-audit
```

The file-install commands above use the published files from the `configuration` directory. `labadmin` is the recorded local group; use the corresponding administrative/log-reading group in another lab. The [service unit](../configuration/soc-web-audit.service) starts the collector after auditd. The audit rule file retains the rule for subsequent boots; check existing rules before adding it again.

### Splunk inputs and checks

Place `indexes.conf`, `inputs.conf` and `props.conf` in `/opt/splunk/etc/apps/soc_web/local/`. Confirm Splunk can read each monitored log, then restart it to load the app configuration. This run used the existing root-run Splunk installation; use appropriate service-user permissions for another deployment.

Open Search & Reporting and check the new index:

```spl
index=soc_web
| stats count by sourcetype
```

This is a collection check for reproduction, not an additional saved test result. Proxy events appear after a real proxy request. The six original investigation searches and their measured results are retained in the search guide.

## Individual browser inputs

Open `http://192.168.144.20:8080/vulnerabilities/exec/`. Submit each input separately and inspect the result before moving on. Do not run these against a real application or public host.

**Normal control:**

```text
127.0.0.1
```

**Identity proof in DetectionOnly:**

```text
127.0.0.1; /usr/bin/id
```

Check the actual WAF rule warning, backend PID, shell child and id process. A 200 page alone is insufficient. The additional short `127.0.0.1; id` calibration in this run executed without an RCE warning; retain that result if comparing rule coverage.

**Harmless internal download:**

```text
127.0.0.1; /usr/bin/id; curl --interface 192.168.144.20 --proxy http://192.168.144.20:3128 --noproxy "" http://192.168.144.1:8090/training-note.txt -o /tmp/soc-training-note.txt
```

The empty noproxy value ensures an environment bypass does not skip the explicitly selected proxy. The interface argument sets the lab source. Inspect the curl arguments and all independent logs. Hash the saved file and compare it with the served bytes. Apache's PrivateTmp means the host-visible file is under its systemd-private directory, not the ordinary host `/tmp`.

**Comparable blocked request:**

Preserve the downloaded file in an evidence directory, record its path/hash/owner and verify that the original application target is absent. Change only the front engine from DetectionOnly to On, validate the configuration and reload Apache. Submit the exact same download input. Observe backend, audit, proxy, file and origin evidence for a bounded period. In this run the window ended about 79 seconds after the blocked request. Then submit the normal control again while blocking remains enabled.

## Finish and review

Open Trigger History and its actual scheduled results. Preserve screenshots and result exports, then stop scheduling without deleting the alert history. Run each of the six investigation searches in Search UI, compare them to native records, and import the supplied Simple XML through a Classic Dashboard's Source editor. The dashboard uses the original fixed windows; adjust them for another run.

Keep the vulnerable application on the isolated lab network. Blocking is a virtual patch for the tested request, not a code repair. The application patch, broader rule tuning and production hardening are outside this completed experiment.
