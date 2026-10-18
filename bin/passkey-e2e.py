#!/usr/bin/env python3
"""End-to-end passkey test: headless Chrome with a virtual authenticator, driven over CDP.

Usage: bin/passkey-e2e.py <site-url>   (environment: PASSKEY_USER, PASSKEY_PASS, CHROME)

The site must be reachable as http://localhost:<port> or https:// (WebAuthn does not
accept IP addresses), and the account must be an administrator without two-factor.
Needs Google Chrome or Chromium; only Python's standard library otherwise.
"""
import base64, json, os, socket, struct, subprocess, sys, tempfile, time, urllib.request
from urllib.parse import urlparse

SITE = sys.argv[1] if len(sys.argv) > 1 else 'http://localhost:8098'
USER, PASSWORD = os.environ.get('PASSKEY_USER', 'pk_user'), os.environ.get('PASSKEY_PASS', 'Pk-pass-12345')
PORT = 9333


class WS:
    def __init__(self, url):
        u = urlparse(url)
        self.s = socket.create_connection((u.hostname, u.port))
        key = base64.b64encode(os.urandom(16)).decode()
        self.s.sendall((f'GET {u.path} HTTP/1.1\r\nHost: {u.hostname}:{u.port}\r\nUpgrade: websocket\r\n'
                        f'Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n').encode())
        head = b''
        while b'\r\n\r\n' not in head:
            head += self.s.recv(1)
        assert b' 101 ' in head.split(b'\r\n')[0], head

    def _read(self, n):
        out = b''
        while len(out) < n:
            chunk = self.s.recv(n - len(out))
            if not chunk:
                raise ConnectionError('closed')
            out += chunk
        return out

    def send(self, text):
        data = text.encode()
        mask = os.urandom(4)
        header = bytes([0x81])
        n = len(data)
        if n < 126:
            header += bytes([0x80 | n])
        elif n < 65536:
            header += bytes([0x80 | 126]) + struct.pack('>H', n)
        else:
            header += bytes([0x80 | 127]) + struct.pack('>Q', n)
        self.s.sendall(header + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))

    def recv(self):
        message = b''
        while True:
            b1, b2 = self._read(2)
            n = b2 & 0x7f
            if n == 126:
                n = struct.unpack('>H', self._read(2))[0]
            elif n == 127:
                n = struct.unpack('>Q', self._read(8))[0]
            payload = self._read(n)
            if (b1 & 0x0f) == 9:  # ping
                continue
            message += payload
            if b1 & 0x80:
                return message.decode()


class CDP:
    def __init__(self, ws):
        self.ws, self.n = ws, 0

    def call(self, method, **params):
        self.n += 1
        self.ws.send(json.dumps({'id': self.n, 'method': method, 'params': params}))
        while True:
            msg = json.loads(self.ws.recv())
            if msg.get('id') == self.n:
                if 'error' in msg:
                    raise RuntimeError(f'{method}: {msg["error"]}')
                return msg.get('result', {})

    def js(self, expression):
        r = self.call('Runtime.evaluate', expression=expression, returnByValue=True, awaitPromise=True)
        return r.get('result', {}).get('value')

    def wait(self, check, timeout=15):
        end = time.time() + timeout
        while time.time() < end:
            try:
                if self.js(check):
                    return True
            except Exception:
                pass
            time.sleep(0.25)
        raise TimeoutError(check)

    def go(self, url):
        self.call('Page.navigate', url=url)
        time.sleep(0.3)
        self.wait('document.readyState === "complete"')


def step(text, ok=True):
    print(('  ok   ' if ok else '  FAIL ') + text)
    if not ok:
        sys.exit(1)


profile = tempfile.mkdtemp(prefix='ss-chrome-')
chrome = subprocess.Popen([os.environ.get('CHROME', 'google-chrome'), '--headless=new', f'--remote-debugging-port={PORT}', f'--user-data-dir={profile}',
                           '--no-first-run', '--no-default-browser-check', '--disable-gpu', 'about:blank'],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    for _ in range(60):
        try:
            targets = json.load(urllib.request.urlopen(f'http://127.0.0.1:{PORT}/json/list'))
            pages = [t for t in targets if t['type'] == 'page']
            if pages:
                break
        except Exception:
            pass
        time.sleep(0.25)
    cdp = CDP(WS(pages[0]['webSocketDebuggerUrl']))
    for domain in ('Page', 'Runtime', 'Network', 'WebAuthn'):
        cdp.call(domain + '.enable')
    auth = cdp.call('WebAuthn.addVirtualAuthenticator', options={
        'protocol': 'ctap2', 'transport': 'internal', 'hasResidentKey': True,
        'hasUserVerification': True, 'isUserVerified': True, 'automaticPresenceSimulation': True})['authenticatorId']
    print('Passkey end-to-end test against', SITE)

    def login():
        cdp.go(SITE + '/wp-login.php')
        cdp.js(f'document.getElementById("user_login").value={json.dumps(USER)};'
               f'document.getElementById("user_pass").value={json.dumps(PASSWORD)};'
               'document.getElementById("wp-submit").click(); true')
        time.sleep(0.5)
        cdp.wait('document.readyState === "complete" && !location.href.endsWith("wp-login.php")')

    login()
    step('logged in with the password only (no second step yet)', '/wp-admin' in cdp.js('location.href'))

    cdp.go(SITE + '/wp-admin/users.php?page=sentinel-shield-2fa')
    step('2FA page asks to confirm it is you', bool(cdp.js('!!document.getElementById("ss-reauth")')))
    step('"Add a passkey" is not offered before confirming', not cdp.js('!!document.querySelector("[data-ss-passkey=create]")'))
    cdp.js(f'var f=document.querySelector("#ss-reauth input[name=password]").form; f.password.value={json.dumps(PASSWORD)}; HTMLFormElement.prototype.submit.call(f); true')
    time.sleep(0.5)
    cdp.wait('document.readyState === "complete" && !!document.querySelector("[data-ss-passkey=create]")')
    step('confirmed with the password; "Add a passkey" now offered', True)

    cdp.js('document.querySelector("#ss-passkeys input[name=name]").value="Virtual key"; document.querySelector("[data-ss-passkey=create]").click(); true')
    time.sleep(1)
    cdp.wait('document.readyState === "complete" && document.body.innerText.includes("Passkey added")', 20)
    creds = cdp.call('WebAuthn.getCredentials', authenticatorId=auth)['credentials']
    step(f'passkey registered (browser created {len(creds)} credential; page lists "Virtual key")',
         len(creds) == 1 and cdp.js('document.getElementById("ss-passkeys").innerText.includes("Virtual key")'))

    cdp.call('Network.clearBrowserCookies')
    login()
    href = cdp.js('location.href')
    step('after the password, the login asks for the second step', 'action=sentinel_shield_2fa' in href)
    step('the code screen offers "Use a passkey"', bool(cdp.js('!!document.querySelector("[data-ss-passkey=get]")')))
    cdp.js('document.querySelector("[data-ss-passkey=get]").click(); true')
    time.sleep(1)
    cdp.wait('document.readyState === "complete" && location.href.includes("/wp-admin")', 20)
    step('signed in with the passkey', '/wp-admin' in cdp.js('location.href'))
    count = cdp.call('WebAuthn.getCredentials', authenticatorId=auth)['credentials'][0]['signCount']
    step(f'the authenticator signed (signature counter now {count})', count >= 1)

    # Wrong authenticator: remove the credential and try again.
    cdp.call('Network.clearBrowserCookies')
    cdp.call('WebAuthn.clearCredentials', authenticatorId=auth)
    login()
    cdp.js('document.querySelector("[data-ss-passkey=get]").click(); true')
    cdp.wait('document.querySelector(".ss-passkey-error") && document.querySelector(".ss-passkey-error").innerText.length > 0', 20)
    step('with no matching passkey the browser refuses and the login stays on the code screen', 'action=sentinel_shield_2fa' in cdp.js('location.href'))
    print('Passkey test passed.')
finally:
    chrome.terminate()
