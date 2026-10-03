import sqlite3
import json
import os
import re
import datetime
from pathlib import Path

class ReconDB:
    def __init__(self, db_path):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute('PRAGMA journal_mode=WAL;')
        self.setup()

    def setup(self):
        cur = self.conn.cursor()
        cur.executescript("""
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    domain TEXT NOT NULL,
    duration_minutes INTEGER DEFAULT 0,
    modules_run TEXT DEFAULT '',
    ingested_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS subdomains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    hostname TEXT NOT NULL,
    source TEXT DEFAULT 'unknown',
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE INDEX IF NOT EXISTS idx_subs_scan ON subdomains(scan_id);
CREATE INDEX IF NOT EXISTS idx_subs_host ON subdomains(hostname);

CREATE TABLE IF NOT EXISTS dns_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    hostname TEXT NOT NULL,
    ip TEXT DEFAULT '',
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE INDEX IF NOT EXISTS idx_dns_scan ON dns_records(scan_id);

CREATE TABLE IF NOT EXISTS web_apps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    status_code INTEGER DEFAULT 0,
    title TEXT DEFAULT '',
    webserver TEXT DEFAULT '',
    tech TEXT DEFAULT '',
    content_length INTEGER DEFAULT 0,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE INDEX IF NOT EXISTS idx_webapps_scan ON web_apps(scan_id);
CREATE INDEX IF NOT EXISTS idx_webapps_status ON web_apps(status_code);

CREATE TABLE IF NOT EXISTS ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    service TEXT DEFAULT '',
    version TEXT DEFAULT '',
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE INDEX IF NOT EXISTS idx_ports_scan ON ports(scan_id);

CREATE TABLE IF NOT EXISTS historical_urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'all',
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE INDEX IF NOT EXISTS idx_hist_scan ON historical_urls(scan_id);
CREATE INDEX IF NOT EXISTS idx_hist_cat ON historical_urls(scan_id, category);
CREATE INDEX IF NOT EXISTS idx_hist_url ON historical_urls(url);

CREATE TABLE IF NOT EXISTS js_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    finding_type TEXT NOT NULL,
    value TEXT NOT NULL,
    source_url TEXT DEFAULT '',
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE INDEX IF NOT EXISTS idx_js_scan ON js_findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_js_type ON js_findings(finding_type);

CREATE TABLE IF NOT EXISTS dork_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    category TEXT NOT NULL,
    url TEXT NOT NULL,
    source_file TEXT DEFAULT '',
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE INDEX IF NOT EXISTS idx_dork_scan ON dork_findings(scan_id);
        """)
        self.conn.commit()

    def ingest_scan(self, target_dir):
        target_path = Path(target_dir)
        domain = target_path.name
        
        timestamp = datetime.datetime.now().isoformat()
        duration_minutes = 0
        modules_run = ''
        summary_path = target_path / 'reports' / 'summary.json'
        if summary_path.exists():
            try:
                with open(summary_path) as f:
                    summary = json.load(f)
                    timestamp = summary.get('timestamp', timestamp)
                    duration_minutes = summary.get('duration_minutes', 0)
                    modules_run = summary.get('modules_run', '')
            except Exception:
                pass
                
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO scans (timestamp, domain, duration_minutes, modules_run, ingested_at) VALUES (?, ?, ?, ?, ?)",
            (timestamp, domain, duration_minutes, modules_run, datetime.datetime.now().isoformat())
        )
        scan_id = cur.lastrowid
        
        subs_path = target_path / 'subs' / 'all.txt'
        if subs_path.exists():
            subs = []
            with open(subs_path) as f:
                for line in f:
                    host = line.strip()
                    if host:
                        subs.append((scan_id, host))
            if subs:
                cur.executemany("INSERT INTO subdomains (scan_id, hostname) VALUES (?, ?)", subs)
                
        dns_path = target_path / 'dns' / 'resolved.txt'
        if dns_path.exists():
            dns = []
            with open(dns_path) as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        dns.append((scan_id, parts[0], parts[1]))
            if dns:
                cur.executemany("INSERT INTO dns_records (scan_id, hostname, ip) VALUES (?, ?, ?)", dns)
                
        httpx_path = target_path / 'httpx' / 'results.json'
        if httpx_path.exists():
            apps = []
            with open(httpx_path) as f:
                for line in f:
                    try:
                        obj = json.loads(line)
                        url = obj.get('url', '')
                        if url:
                            apps.append((
                                scan_id, url, obj.get('status_code', 0),
                                obj.get('title', ''), obj.get('webserver', ''),
                                json.dumps(obj.get('tech', [])) if 'tech' in obj else '',
                                obj.get('content_length', 0)
                            ))
                    except Exception:
                        pass
            if apps:
                cur.executemany("INSERT INTO web_apps (scan_id, url, status_code, title, webserver, tech, content_length) VALUES (?, ?, ?, ?, ?, ?, ?)", apps)
                
        ports_path = target_path / 'ports' / 'naabu.txt'
        if ports_path.exists():
            ports = []
            with open(ports_path) as f:
                for line in f:
                    parts = line.strip().split(':')
                    if len(parts) >= 2:
                        try:
                            ports.append((scan_id, parts[0], int(parts[1])))
                        except ValueError:
                            pass
            if ports:
                cur.executemany("INSERT INTO ports (scan_id, host, port) VALUES (?, ?, ?)", ports)
                
        hist_path = target_path / 'historical' / 'all_urls.txt'
        if hist_path.exists():
            interesting_words = ["admin", "login", "api", "auth", "debug", "config", "backup", "swagger", "graphql", "upload", "internal", "dev", "staging", "test", ".env", ".json", ".xml", "db", "sql"]
            auth_regex = re.compile(r'(login|admin|dashboard|portal|panel|auth)', re.IGNORECASE)
            api_regex = re.compile(r'(/api/|/v[0-9]+/|graphql|rest|swagger|openapi)', re.IGNORECASE)
            sens_regex = re.compile(r'\.(json|xml|yaml|yml|conf|config|env|bak|old|sql|log)$', re.IGNORECASE)
            static_exts = [".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", ".ttf", ".eot", ".ico"]
            
            hist_records = []
            with open(hist_path) as f:
                for line in f:
                    url = line.strip()
                    if not url: continue
                    categories = set(['all'])
                    url_lower = url.lower()
                    
                    if any(w in url_lower for w in interesting_words):
                        categories.add('interesting')
                    if auth_regex.search(url_lower):
                        categories.add('auth')
                    if api_regex.search(url_lower):
                        categories.add('apis')
                    if sens_regex.search(url_lower):
                        categories.add('sensitive')
                    if any(url_lower.endswith(ext) for ext in static_exts):
                        categories.add('static')
                        
                    for cat in categories:
                        hist_records.append((scan_id, url, cat))
            if hist_records:
                cur.executemany("INSERT INTO historical_urls (scan_id, url, category) VALUES (?, ?, ?)", hist_records)
                
        js_files = [
            ('endpoints.txt', 'endpoint'), ('secrets.txt', 'secret'),
            ('leakage.txt', 'leakage'), ('comments.txt', 'comment'),
            ('api_endpoints.txt', 'api_endpoint')
        ]
        js_records = []
        for fname, ftype in js_files:
            jpath = target_path / 'js' / fname
            if jpath.exists():
                with open(jpath) as f:
                    for line in f:
                        val = line.strip()
                        if val:
                            js_records.append((scan_id, ftype, val, ''))
        if js_records:
            cur.executemany("INSERT INTO js_findings (scan_id, finding_type, value, source_url) VALUES (?, ?, ?, ?)", js_records)
            
        dorks_dir = target_path / 'dorks'
        if dorks_dir.exists():
            dork_records = []
            for dfile in dorks_dir.glob('*.txt'):
                if dfile.name == 'all_findings.txt' or dfile.name.startswith('passive_'):
                    with open(dfile) as f:
                        for line in f:
                            url = line.strip()
                            if url:
                                dork_records.append((scan_id, dfile.stem, url, dfile.name))
            if dork_records:
                cur.executemany("INSERT INTO dork_findings (scan_id, category, url, source_file) VALUES (?, ?, ?, ?)", dork_records)
                
        self.conn.commit()
        return scan_id

    def get_scans(self):
        cur = self.conn.cursor()
        cur.execute("SELECT id, timestamp, domain, duration_minutes, modules_run FROM scans ORDER BY timestamp DESC")
        return [dict(row) for row in cur.fetchall()]

    def get_historical(self, tab, query, host, ext, hide_static, hide_dupes, page, page_size):
        target_dir = Path(self.db_path).parent
        
        if tab == 'validated':
            vpath = target_dir / 'historical' / 'validated_interesting.json'
            items = []
            if vpath.exists():
                try:
                    with open(vpath) as f:
                        items = json.load(f)
                except:
                    pass
            if query:
                items = [i for i in items if query.lower() in str(i).lower()]
            total = len(items)
            start = (page - 1) * page_size
            return {
                'counts': {'validated': total},
                'items': items[start:start + page_size],
                'total': total,
                'page': page,
                'pageSize': page_size
            }
            
        base_query = "FROM historical_urls WHERE category = ?"
        params = [tab]
        
        if query:
            base_query += " AND url LIKE ?"
            params.append(f"%{query}%")
        if host:
            base_query += " AND url LIKE ?"
            params.append(f"%{host}%")
        if ext:
            base_query += " AND url LIKE ?"
            params.append(f"%.{ext}%")
        if hide_static:
            for ext_val in ['.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.woff', '.woff2', '.ttf', '.eot', '.ico']:
                base_query += " AND url NOT LIKE ?"
                params.append(f"%{ext_val}")
                
        cur = self.conn.cursor()
        cur.execute(f"SELECT COUNT(*) {base_query}", params)
        total = cur.fetchone()[0]
        
        cur.execute(f"SELECT url, scan_id {base_query} ORDER BY id DESC LIMIT ? OFFSET ?", params + [page_size, (page - 1) * page_size])
        items = [{'url': row['url'], 'scan_id': row['scan_id']} for row in cur.fetchall()]
        
        cur.execute("SELECT category, COUNT(*) as count FROM historical_urls GROUP BY category")
        counts = {row['category']: row['count'] for row in cur.fetchall()}
        
        return {
            'counts': counts,
            'items': items,
            'total': total,
            'page': page,
            'pageSize': page_size
        }

    def get_diff(self, scan_a, scan_b):
        cur = self.conn.cursor()
        diff = {
            'subdomains': {'added': [], 'removed': []},
            'ports': {'added': [], 'removed': []},
            'web_apps': {'added': [], 'removed': [], 'status_changed': []}
        }
        
        cur.execute("SELECT hostname FROM subdomains WHERE scan_id=? EXCEPT SELECT hostname FROM subdomains WHERE scan_id=?", (scan_b, scan_a))
        diff['subdomains']['added'] = [row['hostname'] for row in cur.fetchall()]
        cur.execute("SELECT hostname FROM subdomains WHERE scan_id=? EXCEPT SELECT hostname FROM subdomains WHERE scan_id=?", (scan_a, scan_b))
        diff['subdomains']['removed'] = [row['hostname'] for row in cur.fetchall()]
        
        cur.execute("SELECT host, port FROM ports WHERE scan_id=? EXCEPT SELECT host, port FROM ports WHERE scan_id=?", (scan_b, scan_a))
        diff['ports']['added'] = [{'host': row['host'], 'port': row['port']} for row in cur.fetchall()]
        cur.execute("SELECT host, port FROM ports WHERE scan_id=? EXCEPT SELECT host, port FROM ports WHERE scan_id=?", (scan_a, scan_b))
        diff['ports']['removed'] = [{'host': row['host'], 'port': row['port']} for row in cur.fetchall()]
        
        cur.execute("SELECT url FROM web_apps WHERE scan_id=? EXCEPT SELECT url FROM web_apps WHERE scan_id=?", (scan_b, scan_a))
        diff['web_apps']['added'] = [row['url'] for row in cur.fetchall()]
        cur.execute("SELECT url FROM web_apps WHERE scan_id=? EXCEPT SELECT url FROM web_apps WHERE scan_id=?", (scan_a, scan_b))
        diff['web_apps']['removed'] = [row['url'] for row in cur.fetchall()]
        
        cur.execute('''
            SELECT a.url, a.status_code as old_status, b.status_code as new_status
            FROM web_apps a
            JOIN web_apps b ON a.url = b.url
            WHERE a.scan_id = ? AND b.scan_id = ? AND a.status_code != b.status_code
        ''', (scan_a, scan_b))
        diff['web_apps']['status_changed'] = [
            {'url': row['url'], 'old_status': row['old_status'], 'new_status': row['new_status']} 
            for row in cur.fetchall()
        ]
        
        return diff

    def close(self):
        self.conn.close()
