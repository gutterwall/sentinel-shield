#!/usr/bin/env python3
"""End-to-end passkey test: headless Chrome with virtual authenticators, driven over CDP.

Usage: bin/passkey-e2e.py <site-url>
  environment: PASSKEY_USER, PASSKEY_PASS, CHROME (binary), CHROME_SPKI (base64 SHA-256
  of a self-signed certificate's public key, for https:// test sites), WP_PATH (the
  site's folder: enables the checks that switch settings with wp-cli)

Covers registering and using a passkey; a synchronized passkey used from a second
browser profile; a key that only checks presence (no fingerprint, face or PIN) under
both user verification policies; the password manager hints (autocomplete) on every
form; and refusal without a matching key.

The site must be reachable as http://localhost:<port> or https:// (WebAuthn does not
accept IP addresses), and the account must be an administrator without two-factor.
Needs Google Chrome or Chromium; only Python's standard library otherwise.
"""
import base64, json, os, shutil, socket, struct, subprocess, sys, tempfile, time, urllib.request
from urllib.parse import urlparse

SITE = sys.argv[1] if len(sys.argv) > 1 else 'http://localhost:8098'
USER, PASSWORD = os.environ.get('PASSKEY_USER', 'pk_user'), os.environ.get('PASSKEY_PASS', 'Pk-pass-12345')
PORT = 9333
WP_PATH = os.environ.get('WP_PATH', '')


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


def wp(*args):
    return subprocess.run(['wp', '--path=' + WP_PATH, *args], check=True, capture_output=True, text=True).stdout.strip()


class Browser:
    """A headless Chrome with its own profile and a virtual authenticator."""

    def __init__(self, port, uv=True):
        self.profile = tempfile.mkdtemp(prefix='ss-chrome-')
        flags = ['--headless=new', f'--remote-debugging-port={port}', f'--user-data-dir={self.profile}',
                 '--no-first-run', '--no-default-browser-check', '--disable-gpu']
        if os.environ.get('CHROME_SPKI'):
            flags.append('--ignore-certificate-errors-spki-list=' + os.environ['CHROME_SPKI'])
        self.proc = subprocess.Popen([os.environ.get('CHROME', 'google-chrome'), *flags, 'about:blank'],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        pages = []
        for _ in range(60):
            try:
                pages = [t for t in json.load(urllib.request.urlopen(f'http://127.0.0.1:{port}/json/list')) if t['type'] == 'page']
                if pages:
                    break
            except Exception:
                pass
            time.sleep(0.25)
        self.cdp = CDP(WS(pages[0]['webSocketDebuggerUrl']))
        for domain in ('Page', 'Runtime', 'Network', 'WebAuthn'):
            self.cdp.call(domain + '.enable')
        self.auth = self.authenticator(uv)

    def authenticator(self, uv):
        """A new virtual authenticator: a platform passkey (uv) or a touch-only security key."""
        return self.cdp.call('WebAuthn.addVirtualAuthenticator', options={
            'protocol': 'ctap2', 'transport': 'internal' if uv else 'usb', 'hasResidentKey': uv,
            'hasUserVerification': uv, 'isUserVerified': uv, 'automaticPresenceSimulation': True})['authenticatorId']

    def login(self):
        cdp = self.cdp
        cdp.go(SITE + '/wp-login.php')
        cdp.wait('!!document.getElementById("wp-submit")')
        cdp.js(f'document.getElementById("user_login").value={json.dumps(USER)};'
               f'document.getElementById("user_pass").value={json.dumps(PASSWORD)};'
               'document.getElementById("wp-submit").click(); true')
        time.sleep(0.5)
        cdp.wait('document.readyState === "complete" && !location.href.endsWith("wp-login.php")')

    def confirm_identity(self):
        cdp = self.cdp
        cdp.go(SITE + '/wp-admin/users.php?page=sentinel-shield-2fa')
        cdp.wait('!!document.getElementById("ss-reauth")')
        cdp.js(f'var f=document.querySelector("#ss-reauth input[name=password]").form; f.password.value={json.dumps(PASSWORD)}; HTMLFormElement.prototype.submit.call(f); true')
        time.sleep(0.5)
        cdp.wait('document.readyState === "complete" && !!document.querySelector("[data-ss-passkey=create]")')

    def add_passkey(self, name):
        self.cdp.js(f'document.querySelector("#ss-passkeys input[name=name]").value={json.dumps(name)}; document.querySelector("[data-ss-passkey=create]").click(); true')
        time.sleep(1)
        self.cdp.wait('document.readyState === "complete" && (document.body.innerText.includes("Passkey added") || document.body.innerText.includes("could not be added"))', 20)
        return self.cdp.js('document.body.innerText.includes("Passkey added")')

    def passkey_step(self):
        """Clicks "Use a passkey" on the code screen; True when it logged in."""
        self.cdp.js('document.querySelector("[data-ss-passkey=get]").click(); true')
        end = time.time() + 20
        while time.time() < end:
            state = self.cdp.js('document.readyState === "complete" ? (location.href.includes("/wp-admin") ? "in" : (document.querySelector(".ss-passkey-error") && document.querySelector(".ss-passkey-error").innerText.length > 0) || document.body.innerText.includes("could not be verified") ? "refused" : "") : ""')
            if state:
                return state == 'in'
            time.sleep(0.25)
        return False

    def close(self):
        self.proc.terminate()
        try:
            self.proc.wait(10)
        except Exception:
            pass
        shutil.rmtree(self.profile, ignore_errors=True)


a = Browser(PORT)
others = []
try:
    cdp, auth = a.cdp, a.auth
    print('Passkey end-to-end test against', SITE)
    cdp.go(SITE + '/wp-login.php')
    cdp.wait('!!document.getElementById("user_pass")')
    step('password manager hints on the login form (username, current-password)',
         cdp.js('document.getElementById("user_login").autocomplete === "username" && document.getElementById("user_pass").autocomplete === "current-password"'))
    a.login()
    step('logged in with the password only (no second step yet)', '/wp-admin' in cdp.js('location.href'))

    cdp.go(SITE + '/wp-admin/users.php?page=sentinel-shield-2fa')
    cdp.wait('document.readyState === "complete" && !!document.getElementById("ss-reauth")')
    step('2FA page asks to confirm it is you', bool(cdp.js('!!document.getElementById("ss-reauth")')))
    step('the confirmation form tells password managers it wants the current password',
         cdp.js('document.querySelector("#ss-reauth input[name=password]").autocomplete === "current-password"'))
    step('"Add a passkey" is not offered before confirming', not cdp.js('!!document.querySelector("[data-ss-passkey=create]")'))
    a.confirm_identity()
    step('confirmed with the password; "Add a passkey" now offered', True)

    step('passkey registered', a.add_passkey('Virtual key'))
    creds = cdp.call('WebAuthn.getCredentials', authenticatorId=auth)['credentials']
    step(f'the browser holds {len(creds)} credential and the page lists "Virtual key"',
         len(creds) == 1 and cdp.js('document.getElementById("ss-passkeys").innerText.includes("Virtual key")'))

    cdp.call('Network.clearBrowserCookies')
    a.login()
    step('after the password, the login asks for the second step', 'action=sentinel_shield_2fa' in cdp.js('location.href'))
    step('the code screen offers "Use a passkey"', bool(cdp.js('!!document.querySelector("[data-ss-passkey=get]")')))
    step('the code field tells password managers it wants a one-time code',
         cdp.js('!document.getElementById("sentinel-shield-code") || document.getElementById("sentinel-shield-code").autocomplete === "one-time-code"'))
    step('signed in with the passkey', a.passkey_step())
    cred = cdp.call('WebAuthn.getCredentials', authenticatorId=auth)['credentials'][0]
    step(f'the authenticator signed (signature counter now {cred["signCount"]})', cred['signCount'] >= 1)

    # A synchronized passkey: the same credential in another browser profile
    # (as a passkey manager copies it), used there with no other set-up.
    b = Browser(PORT + 1)
    others.append(b)
    b.cdp.call('WebAuthn.addCredential', authenticatorId=b.auth, credential={
        'credentialId': cred['credentialId'], 'isResidentCredential': True, 'rpId': cred['rpId'],
        'privateKey': cred['privateKey'], 'userHandle': cred.get('userHandle', ''), 'signCount': cred['signCount']})
    b.login()
    step('a second browser with the synchronized passkey reaches the second step', 'action=sentinel_shield_2fa' in b.cdp.js('location.href'))
    step('and signs in with it', b.passkey_step())
    # Passkey providers sync the credential, counter included (synced passkeys usually
    # report 0). Two virtual authenticators count on their own, and a counter that does
    # not go up is refused as a possible clone; so bring the first one up to date.
    synced = b.cdp.call('WebAuthn.getCredentials', authenticatorId=b.auth)['credentials'][0]
    cdp.call('WebAuthn.clearCredentials', authenticatorId=auth)
    cdp.call('WebAuthn.addCredential', authenticatorId=auth, credential={
        'credentialId': synced['credentialId'], 'isResidentCredential': True, 'rpId': synced['rpId'],
        'privateKey': synced['privateKey'], 'userHandle': synced.get('userHandle', ''), 'signCount': synced['signCount']})

    # A security key that only checks presence (a touch, no PIN or fingerprint).
    cdp.call('Network.clearBrowserCookies')
    a.login()
    a.passkey_step()
    cdp.go(SITE + '/wp-admin/users.php?page=sentinel-shield-2fa')
    cdp.wait('!!document.querySelector("#ss-reauth [data-ss-passkey=get]")')
    cdp.js('document.querySelector("#ss-reauth [data-ss-passkey=get]").click(); true')
    cdp.wait('document.readyState === "complete" && !!document.querySelector("[data-ss-passkey=create]")', 20)
    step('a passkey with fingerprint, face or PIN confirms identity on its own', True)
    latest = cdp.call('WebAuthn.getCredentials', authenticatorId=auth)['credentials'][0]
    cdp.call('WebAuthn.removeVirtualAuthenticator', authenticatorId=auth)
    touch = a.authenticator(False)
    step('a touch-only security key can be added while verification is preferred', a.add_passkey('Touch key'))
    cdp.call('Network.clearBrowserCookies')
    a.login()
    step('the touch-only key signs in after the password (verification preferred)', a.passkey_step())
    cdp.go(SITE + '/wp-admin/users.php?page=sentinel-shield-2fa')
    cdp.wait('!!document.querySelector("#ss-reauth [data-ss-passkey=get]")')
    cdp.js('document.querySelector("#ss-reauth [data-ss-passkey=get]").click(); true')
    time.sleep(1.5)
    cdp.wait('document.readyState === "complete"')
    step('but it cannot confirm identity on its own (that needs fingerprint, face or PIN)',
         not cdp.js('!!document.querySelector("[data-ss-passkey=create]")'))
    if WP_PATH:
        wp('sentinel', 'settings-set', 'twofa.passkey_uv', 'required')
        try:
            cdp.call('Network.clearBrowserCookies')
            a.login()
            step('with verification required, the browser is asked for it', cdp.js(
                'JSON.parse(document.querySelector("[data-ss-passkey=get]").dataset.options).userVerification === "required"'))
            step('and the touch-only key is refused at login', not a.passkey_step())
            b.cdp.call('WebAuthn.clearCredentials', authenticatorId=b.auth)
            b.cdp.call('WebAuthn.addCredential', authenticatorId=b.auth, credential={
                'credentialId': latest['credentialId'], 'isResidentCredential': True, 'rpId': latest['rpId'],
                'privateKey': latest['privateKey'], 'userHandle': latest.get('userHandle', ''), 'signCount': latest['signCount']})
            b.cdp.call('Network.clearBrowserCookies')
            b.login()
            step('a synchronized platform passkey (with verification) still signs in', b.passkey_step())
        finally:
            wp('sentinel', 'settings-set', 'twofa.passkey_uv', 'preferred')

    # No matching key at all.
    cdp.call('Network.clearBrowserCookies')
    cdp.call('WebAuthn.clearCredentials', authenticatorId=touch)
    a.login()
    step('with no matching passkey the browser refuses and the login stays on the code screen', not a.passkey_step() and 'action=sentinel_shield_2fa' in cdp.js('location.href'))
    print('Passkey test passed.')
finally:
    a.close()
    for other in others:
        other.close()
