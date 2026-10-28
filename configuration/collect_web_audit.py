"""Normalize native auditd EXECVE groups; never generates lab activity."""
import json,re,time,shlex,os
from pathlib import Path
source=Path('/var/log/audit/audit.log')
output=Path('/opt/soc-web-lab/logs/process-audit.jsonl')
pattern=re.compile(r'msg=audit\(([0-9.]+):(\d+)\)')
groups={}
def string(v):
    if v.startswith('"') and v.endswith('"'):return v[1:-1]
    try:return bytes.fromhex(v).decode('utf-8')
    except (ValueError,UnicodeDecodeError):return v
def emit(event):
    lines=event['raw_records']
    syscall=next((l for l in lines if l.startswith('type=SYSCALL ')),None)
    if not syscall or 'soc_web_exec' not in syscall:return
    def field(name):
        m=re.search(r'\b'+name+r'=("[^"]*"|\S+)',syscall)
        if not m:return None
        v=m.group(1)
        return string(v) if name in ('exe','comm') else v.strip('"')
    argv={}
    for line in lines:
        if line.startswith('type=EXECVE '):
            for m in re.finditer(r'\ba(\d+)=("[^"]*"|\S+)',line):argv[int(m.group(1))]=string(m.group(2))
    event.update({'host':os.uname().nodename,'pid':int(field('pid')),'ppid':int(field('ppid')),'uid':int(field('uid')),'euid':int(field('euid')),'exe':field('exe'),'comm':field('comm'),'success':field('success'),'argv':[argv[n] for n in sorted(argv)]})
    event['command']=shlex.join(event['argv'])
    with output.open('a',encoding='utf-8') as f:f.write(json.dumps(event,ensure_ascii=False)+'\n')
with source.open(encoding='utf-8',errors='replace') as f:
    while True:
        line=f.readline()
        if line:
            m=pattern.search(line)
            if m:
                serial=m.group(2)
                e=groups.setdefault(serial,{'timestamp':float(m.group(1)),'audit_serial':serial,'raw_records':[]})
                e['raw_records'].append(line.rstrip('\n'));e['_seen']=time.monotonic()
        else:
            now=time.monotonic()
            for serial,e in list(groups.items()):
                if now-e['_seen']>1:
                    del e['_seen'];emit(e);del groups[serial]
            time.sleep(.2)
