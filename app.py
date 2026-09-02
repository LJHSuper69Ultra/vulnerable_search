import os
import sqlite3
import requests
import subprocess
from flask import Flask, request, render_template, redirect, url_for

app = Flask(__name__)
app.secret_key = 'super_secret_ctf_key'

def init_db():
    conn = sqlite3.connect('ctf_search.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS search_index (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            url TEXT,
            content TEXT,
            is_private INTEGER DEFAULT 0
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS secrets (
            id INTEGER PRIMARY KEY,
            secret_name TEXT,
            value TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS suggestions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            site_url TEXT,
            comment TEXT
        )
    ''')

    cursor.execute("DELETE FROM search_index")
    cursor.execute("DELETE FROM secrets")
    
    cursor.execute("INSERT INTO search_index (title, url, content, is_private) VALUES ('Google Engine', 'https://google.com', 'World largest search portal', 0)")
    cursor.execute("INSERT INTO search_index (title, url, content, is_private) VALUES ('GitHub Repository', 'https://github.com', 'Code hosting and collaboration', 0)")
    cursor.execute("INSERT INTO search_index (title, url, content, is_private) VALUES ('Render Cloud', 'https://render.com', 'Cloud application hosting platform', 0)")
    cursor.execute("INSERT INTO search_index (title, url, content, is_private) VALUES ('Internal Top Secret Doc', 'http://internal.local/secret', 'Confidential project details', 1)")
    
    # FLAG 1: SQL Injection
    cursor.execute("INSERT INTO secrets (id, secret_name, value) VALUES (1, 'FLAG_1_SQLI', 'FLAG{3xpl01t_sqli_un10n_succ3ss}')")
    
    conn.commit()
    conn.close()

init_db()

# Set FLAG 2 in Environment
os.environ['FLAG_2_RCE'] = 'FLAG{c0mm4nd_1nj3ct10n_rce_m4st3r}'

@app.route('/')
def index():
    return render_template('index.html')

# 1. SQL Injection & Reflected XSS
@app.route('/search')
def search():
    query = request.args.get('q', '')
    results = []
    
    if query:
        conn = sqlite3.connect('ctf_search.db')
        cursor = conn.cursor()
        
        # VULNERABLE: Direct string formatting into SQL query (SQL Injection)
        raw_sql = f"SELECT title, url, content FROM search_index WHERE (title LIKE '%{query}%' OR content LIKE '%{query}%') AND is_private = 0"
        
        try:
            cursor.execute(raw_sql)
            results = cursor.fetchall()
        except Exception as e:
            results = [("SQL Error Triggered", "#", str(e))]
        finally:
            conn.close()

    # VULNERABLE: Reflected XSS (query string rendered unsanitized with | safe in template)
    return render_template('results.html', query=query, results=results)

# 2. SSRF (Live External Site Fetcher)
@app.route('/fetch')
def fetch_site():
    target_url = request.args.get('url', '')
    content = ""
    error = ""
    
    if target_url:
        try:
            # VULNERABLE: SSRF - No URL whitelist/validation
            resp = requests.get(target_url, timeout=3)
            content = resp.text[:2000]
        except Exception as e:
            error = str(e)
            
    return render_template('fetch.html', url=target_url, content=content, error=error)

# 3. Command Injection
@app.route('/tools/ping')
def ping_tool():
    host = request.args.get('host', '')
    output = ""
    
    if host:
        # VULNERABLE: OS Command Injection via shell=True
        cmd = f"ping -c 1 {host}"
        try:
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=3).decode('utf-8')
        except Exception as e:
            output = getattr(e, 'output', str(e))
            if isinstance(output, bytes):
                output = output.decode('utf-8')

    return render_template('tools.html', host=host, output=output)

# 4. IDOR
@app.route('/history')
def search_history():
    log_id = request.args.get('id', '1')
    
    fake_logs = {
        "1": {"user": "guest", "query": "how to build a search engine", "time": "2026-09-01 10:00"},
        "2": {"user": "guest", "query": "render deployment guide", "time": "2026-09-01 10:05"},
        "999": {"user": "admin", "query": "Admin Note: FLAG_3_IDOR{1d0r_4cc3ss_gr4nt3d_s3cr3t}", "time": "2026-09-01 00:00"}
    }
    
    log_data = fake_logs.get(str(log_id), {"user": "N/A", "query": "Log record not found", "time": "N/A"})
    return render_template('history.html', log_id=log_id, log=log_data)

# 5. Stored XSS
@app.route('/suggest', methods=['GET', 'POST'])
def suggest():
    if request.method == 'POST':
        site_url = request.form.get('site_url', '')
        comment = request.form.get('comment', '')
        
        conn = sqlite3.connect('ctf_search.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO suggestions (site_url, comment) VALUES (?, ?)", (site_url, comment))
        conn.commit()
        conn.close()
        return redirect(url_for('suggest'))
        
    conn = sqlite3.connect('ctf_search.db')
    cursor = conn.cursor()
    cursor.execute("SELECT site_url, comment FROM suggestions ORDER BY id DESC LIMIT 10")
    items = cursor.fetchall()
    conn.close()
    
    return render_template('suggest.html', suggestions=items)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
