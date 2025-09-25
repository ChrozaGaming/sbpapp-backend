<h1 align="center">🚀 sbpapp-backend</h1>
<p align="center">
  <b>Attendance & Auth backend</b> built with <b>Rust</b>, <b>Actix-web</b>, and <b>MariaDB/MySQL</b>.<br/>
  Secure JWT auth, Argon2 password hashing, subnet/public IP attendance gating, and tidy SQLx async data access.
</p>

<hr/>

<h2>✨ Features</h2>
<ul>
  <li>🔐 <b>Auth</b>: Register/Login with Argon2id password hashing & JWT (stateless).</li>
  <li>🌐 <b>CORS</b>: Multiple origins for local & LAN dev via <code>ALLOWED_ORIGINS</code>.</li>
  <li>🧭 <b>Attendance (Absensi)</b>:
    <ul>
      <li>Fields: date/time, status (<code>hadir | telat | izin</code>), optional geolocation.</li>
      <li>Client IP auto-detected server-side, verified against:
        <ul>
          <li><code>ALLOWED_PUBLIC_IP</code> (e.g. office/home public IP)</li>
          <li><code>ALLOWED_SUBNET</code> (e.g. 192.168.1.0/24 for on-LAN)</li>
        </ul>
      </li>
    </ul>
  </li>
  <li>🧱 <b>Duplicate protection</b>: Unique (<code>email, tanggal_absensi</code>) → 409 Conflict if same-day re-absen.</li>
  <li>🧰 <b>Config-driven</b>: .env config, /health endpoint, optional X-Forwarded-For trust.</li>
</ul>

<h2>🧩 Tech Stack</h2>
<table>
  <tr><td>Language</td><td>Rust (stable)</td></tr>
  <tr><td>Web</td><td>Actix-web 4</td></tr>
  <tr><td>DB Access</td><td>SQLx 0.7 (MySQL/MariaDB runtime)</td></tr>
  <tr><td>Auth</td><td>jsonwebtoken (HS256), argon2</td></tr>
  <tr><td>Config</td><td>dotenvy</td></tr>
  <tr><td>Net utils</td><td>ipnet</td></tr>
  <tr><td>Logs</td><td>env_logger</td></tr>
</table>

<h2>🚀 Getting Started</h2>
<ol>
  <li>Install Rust (<a href="https://rustup.rs/">https://rustup.rs/</a>)</li>
  <li>Prepare .env file</li>
  <li>Run in dev: <code>cargo run</code></li>
  <li>Optional hot reload: <code>cargo install cargo-watch && cargo watch -x run</code></li>
</ol>

<h3>Example .env</h3>
<pre>
DB_HOST=localhost
DB_PORT=3306
DB_NAME=sbpapp
DB_USER=root
DB_PASSWORD=
# DATABASE_URL=mysql://root@localhost:3306/sbpapp

ALLOWED_ORIGINS=http://localhost:3000,http://192.168.1.77:3000
JWT_SECRET=super_secret_dev_key
ALLOWED_PUBLIC_IP=180.248.30.229
ALLOWED_SUBNET=192.168.1.0/24
TRUST_X_FORWARDED_FOR=0
HOST=0.0.0.0
PORT=8080
</pre>

<h2>🔄 Hot Reload (Dev)</h2>
<pre><code>cargo install cargo-watch
cargo watch -x run
</code></pre>

<h2>🧪 API Quick Reference</h2>
<p><b>Base URL:</b> <code>http://HOST:PORT</code></p>

<h3>Health</h3>
<pre>GET /health → 200 "ok"</pre>

<h3>Auth</h3>
<pre>
POST /api/register → 201 { id, name, email }
POST /api/login → 200 { token, user }
GET /api/me (Bearer token) → 200 { id, name, email }
</pre>

<h3>Absensi</h3>
<pre>
POST /api/absensi
Body:
{
  "tanggal_absensi": "YYYY-MM-DD",
  "nama_lengkap": "string",
  "email": "user@example.com",
  "waktu_absensi": "YYYY-MM-DD HH:MM:SS",
  "location_device_lat": -7.9,
  "location_device_lng": 112.6,
  "status": "hadir" | "telat" | "izin"
}
→ 201 Created
→ 403 Forbidden
→ 409 Conflict
→ 400 Bad Request
</pre>

<h2>🧯 Error Responses</h2>
<pre>
{ "message": "Unauthorized: Password salah" }
{ "message": "Forbidden: IP 1.2.3.4 tidak diizinkan" }
{ "message": "Conflict: absensi untuk email & tanggal ini sudah ada" }
{ "message": "Bad request: waktu_absensi harus format: YYYY-MM-DD HH:MM[:SS]" }
{ "message": "Internal server error: DB insert error: ..." }
</pre>

<h2>🔐 Security Notes</h2>
<ul>
  <li>Passwords hashed with <b>Argon2id</b></li>
  <li>JWT secret via <code>JWT_SECRET</code></li>
  <li>X-Forwarded-For trust optional</li>
</ul>
