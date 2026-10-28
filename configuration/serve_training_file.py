"""Serve one harmless training file on the isolated VMware host interface."""
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from datetime import datetime,timezone
import json,hashlib
root=Path(__file__).resolve().parent/'web-lab'
root.mkdir(exist_ok=True)
body=b'SOC training note. This plain text file is harmless and contains no executable code.\n'
(root/'training-note.txt').write_bytes(body)
(root/'origin-file.json').write_text(json.dumps({'filename':'training-note.txt','bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()},indent=2))
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path!='/training-note.txt':self.send_error(404);return
        self.send_response(200);self.send_header('Content-Type','text/plain');self.send_header('Content-Length',str(len(body)));self.send_header('Cache-Control','no-store');self.end_headers();self.wfile.write(body)
    def log_message(self,fmt,*args):
        event={'timestamp':datetime.now(timezone.utc).isoformat(),'client_ip':self.client_address[0],'client_port':self.client_address[1],'request':self.requestline,'message':fmt%args}
        with (root/'origin-access.jsonl').open('a',encoding='utf-8') as f:f.write(json.dumps(event)+'\n')
ThreadingHTTPServer(('192.168.144.1',8090),Handler).serve_forever()
