#!/usr/bin/env python3
#
# test_stored_state.py - functional tests for the stored ("S") thinfo
# encoding of the topology_hiding module.
#
# Starts its own redis-server on 127.0.0.1 and an OpenSIPS proxy doing
# dialog-less topology hiding, then drives SIP flows through it over UDP.
#
# Environment:
#   OPENSIPS      opensips binary (default: ../../../opensips)
#   MPATH         modules directory (default: ../../)
#   REDIS_SERVER  redis-server binary (default: redis-server)
#   REDIS_CLI     redis-cli binary (default: redis-cli)
#   PORT_BASE     first of the 6 UDP/TCP ports used (default: 25060)
#   TH_TEST_DIR   keep the cfgs and logs there (default: a temporary dir,
#                 removed when all checks pass)
#
# Usage:
#   ./test_stored_state.py [scenario ...]
#   ./test_stored_state.py --dump <file> compact   (Contacts seen, for diffs)
#

import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
OPENSIPS = os.environ.get('OPENSIPS', os.path.join(HERE, '../../../opensips'))
MPATH = os.environ.get('MPATH', os.path.join(HERE, '../../')).rstrip('/') + '/'
REDIS_SERVER = os.environ.get('REDIS_SERVER', 'redis-server')
REDIS_CLI = os.environ.get('REDIS_CLI', 'redis-cli')
BASE = int(os.environ.get('PORT_BASE', '25060'))

PROXY = ('127.0.0.1', BASE)
REDIS_PORT = BASE + 3
PASSWD = 'Tst-th-pw'
KEY_RE = re.compile(r'^_[0-9a-f]{16}$')

results = []
contacts_seen = []
work = os.environ.get('TH_TEST_DIR') or tempfile.mkdtemp(prefix='th_stored.')
os.makedirs(work, exist_ok=True)


def check(desc, ok, detail=''):
    results.append((desc, bool(ok)))
    print('  %s: %s%s' % ('PASS' if ok else 'FAIL', desc,
                          '' if ok else ' (%s)' % detail))


# --- redis ---------------------------------------------------------------

def rcli(*args, port=REDIS_PORT):
    out = subprocess.run([REDIS_CLI, '-h', '127.0.0.1', '-p', str(port)]
                         + list(args), capture_output=True, text=True)
    return out.stdout.strip()


def redis_start(port=REDIS_PORT):
    p = subprocess.Popen([REDIS_SERVER, '--bind', '127.0.0.1', '--port',
                          str(port), '--save', '', '--appendonly', 'no',
                          '--dir', work], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
    for _ in range(50):
        if rcli('PING', port=port) == 'PONG':
            return p
        time.sleep(0.1)
    raise SystemExit('redis-server did not start')


def th_keys():
    out = rcli('KEYS', 'th:*')
    return sorted(out.split()) if out else []


def ttl(key):
    return int(rcli('TTL', 'th:' + key[1:]))


# --- opensips ------------------------------------------------------------

CFG = '''
log_level = 3
xlog_level = 3
stderror_enabled = yes
syslog_enabled = no
udp_workers = 2
socket = udp:127.0.0.1:%(port)d
mpath = "%(mpath)s"

loadmodule "proto_udp.so"
loadmodule "signaling.so"
loadmodule "sl.so"
loadmodule "tm.so"
loadmodule "rr.so"
loadmodule "maxfwd.so"
loadmodule "sipmsgops.so"
loadmodule "cachedb_redis.so"
loadmodule "topology_hiding.so"
modparam("tm", "fr_timeout", 2)
%(params)s

route {
	if (!mf_process_maxfwd_header(10)) {
		sl_send_reply(483, "Too Many Hops");
		exit;
	}
	if (has_totag()) {
		if (topology_hiding_match()) {
			xlog("L_INFO", "decoded <$TH_decoded_contact> routes $TH_decoded_routes_count\n");
			t_relay();
			exit;
		}
		if (is_method("ACK")) {
			if (t_check_trans())
				t_relay();
			exit;
		}
		sl_send_reply(404, "Not here");
		exit;
	}
	topology_hiding();
	if (!t_relay())
		sl_reply_error();
}
'''


def th_params(enc, url=None, extra=()):
    p = ['modparam("topology_hiding", "th_contact_encode_param_password", '
         '"thinfo:%s:%s")' % (PASSWD, enc)]
    if url is not None:
        p.append('modparam("topology_hiding", "th_state_url", "%s")' % url)
    for name, val in extra:
        v = val if isinstance(val, int) else '"%s"' % val
        p.append('modparam("topology_hiding", "%s", %s)' % (name, v))
    return '\n'.join(p)


REDIS_URL = 'redis:th://127.0.0.1:%d/' % REDIS_PORT


class Proxy:
    def __init__(self, name, params, must_start=True):
        self.log = os.path.join(work, name + '.log')
        cfg = os.path.join(work, name + '.cfg')
        with open(cfg, 'w') as f:
            f.write(CFG % {'port': BASE, 'mpath': MPATH, 'params': params})
        self.p = subprocess.Popen([OPENSIPS, '-F', '-f', cfg, '-w', work],
                                  stdout=subprocess.DEVNULL,
                                  stderr=open(self.log, 'w'))
        time.sleep(1.5)
        if must_start:
            check('proxy %s started' % name, self.alive(),
                  ''.join(self.lines('ERROR:')[-3:]).strip())

    def alive(self):
        return self.p.poll() is None

    def stop(self):
        if self.alive():
            self.p.terminate()
            try:
                self.p.wait(10)
            except subprocess.TimeoutExpired:
                self.p.kill()
                self.p.wait()

    def lines(self, pattern):
        with open(self.log, errors='replace') as f:
            return [ln for ln in f if pattern in ln]


# --- SIP -----------------------------------------------------------------

COMPACT = {'v': 'via', 'f': 'from', 't': 'to', 'i': 'call-id', 'm': 'contact',
           'l': 'content-length'}


class Msg:
    def __init__(self, data):
        head = data.split('\r\n\r\n', 1)[0].split('\r\n')
        self.first = head[0]
        self.hdrs = []
        for ln in head[1:]:
            n, v = ln.split(':', 1)
            n = n.strip().lower()
            self.hdrs.append((COMPACT.get(n, n), v.strip()))
        f = self.first.split(' ')
        self.is_reply = f[0].startswith('SIP/')
        self.code = int(f[1]) if self.is_reply else 0
        self.method = None if self.is_reply else f[0]
        self.ruri = None if self.is_reply else f[1]

    def get(self, name):
        return [v for n, v in self.hdrs if n == name]

    def hdr(self, name):
        v = self.get(name)
        return v[0] if v else None

    def contact_uri(self):
        c = self.hdr('contact')
        if not c:
            return None
        m = re.search(r'<([^>]*)>', c)
        return m.group(1) if m else c.split(';')[0]

    def thinfo(self):
        m = re.search(r';thinfo=([^;>]+)', self.contact_uri() or '')
        return m.group(1) if m else None


class UA:
    def __init__(self, name, port, user):
        self.name, self.port = name, port
        self.contact = 'sip:%s@127.0.0.1:%d;transport=udp' % (user, port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('127.0.0.1', port))
        self.sock.settimeout(3)

    def send(self, text):
        self.last = text
        self.sock.sendto(text.encode(), PROXY)

    def recv(self):
        while True:
            try:
                data = self.sock.recv(65535).decode(errors='replace')
            except socket.timeout:
                return None
            m = Msg(data)
            if m.is_reply and m.code < 200:
                continue
            contacts_seen.append('%s %s %s' % (self.name, m.first,
                                               m.hdr('contact')))
            return m


class Dialog:
    def __init__(self, local, remote_uri, callid=None):
        self.local = local
        self.callid = callid or uuid.uuid4().hex + '@th.test'
        self.ltag = uuid.uuid4().hex[:10]
        self.rtag = None
        self.luri = 'sip:%s@th.test' % local.name
        self.ruri_aor = remote_uri
        self.target = remote_uri
        self.cseq = 1

    def request(self, method, hdrs=(), cseq=None, contact=True):
        if cseq is None:
            self.cseq += 1
            cseq = self.cseq
        lines = ['%s %s SIP/2.0' % (method, self.target),
                 'Via: SIP/2.0/UDP 127.0.0.1:%d;branch=z9hG4bK%s;rport'
                 % (self.local.port, uuid.uuid4().hex[:12]),
                 'Max-Forwards: 70',
                 'From: <%s>;tag=%s' % (self.luri, self.ltag),
                 'To: <%s>%s' % (self.ruri_aor,
                                 ';tag=' + self.rtag if self.rtag else ''),
                 'Call-ID: %s' % self.callid,
                 'CSeq: %d %s' % (cseq, method)]
        if contact:
            lines.append('Contact: <%s>' % self.local.contact)
        lines += list(hdrs) + ['Content-Length: 0', '', '']
        self.local.send('\r\n'.join(lines))


def reply(ua, req, code, reason='OK', hdrs=(), contact=True, tag=None):
    lines = ['SIP/2.0 %d %s' % (code, reason)]
    lines += ['Via: %s' % v for v in req.get('via')]
    lines.append('From: %s' % req.hdr('from'))
    to = req.hdr('to')
    if ';tag=' not in to and tag:
        to += ';tag=' + tag
    lines += ['To: %s' % to, 'Call-ID: %s' % req.hdr('call-id'),
              'CSeq: %s' % req.hdr('cseq')]
    if contact:
        lines.append('Contact: <%s>' % ua.contact)
    lines += list(hdrs) + ['Content-Length: 0', '', '']
    ua.sock.sendto('\r\n'.join(lines).encode(), PROXY)


def same_target(ruri, contact):
    """the compact codec leaves the default ;transport=udp out"""
    norm = lambda u: re.sub(r';transport=udp', '', u or '', flags=re.I)
    return ruri is not None and norm(ruri) == norm(contact)


def transact(dlg, peer, method, hdrs=(), code=200, rhdrs=(), rcontact=True,
             peer_tag=None, contact=True):
    """dlg's UA sends @method; peer answers @code. Returns (req, rpl)."""
    dlg.request(method, hdrs, contact=contact)
    req = peer.recv()
    if req is None or req.method != method:
        return req, None
    reply(peer, req, code, 'OK' if code < 300 else 'Nope', rhdrs,
          contact=rcontact and code < 300, tag=peer_tag)
    rpl = dlg.local.recv()
    return req, rpl


# --- scenarios -------------------------------------------------------------

def new_pair():
    sub = UA('sub', BASE + 1, '9c3f2b1e-5a6d-4e7f-8a9b-0c1d2e3f4a5b')
    ntf = UA('ntf', BASE + 2, 'presence-server')
    return sub, ntf


def subscribe_dialog(sub, ntf, expires=600):
    """Initial SUBSCRIBE and its 200; returns the two dialog views."""
    d_sub = Dialog(sub, 'sip:%s@127.0.0.1:%d' % (ntf.name, ntf.port))
    ntf_tag = uuid.uuid4().hex[:10]
    req, rpl = transact(d_sub, ntf, 'SUBSCRIBE',
                        ['Event: presence', 'Expires: %d' % expires],
                        rhdrs=['Expires: %d' % expires], peer_tag=ntf_tag)
    if not req or not rpl:
        return None, None, req, rpl
    d_sub.rtag = ntf_tag
    d_sub.target = rpl.contact_uri()
    d_ntf = Dialog(ntf, 'sip:sub@th.test', callid=d_sub.callid)
    d_ntf.ltag, d_ntf.rtag = ntf_tag, d_sub.ltag
    d_ntf.luri, d_ntf.ruri_aor = 'sip:%s@th.test' % ntf.name, d_sub.luri
    d_ntf.target = req.contact_uri()
    return d_sub, d_ntf, req, rpl


def notify(d_ntf, sub, state, rcontact=True):
    return transact(d_ntf, sub, 'NOTIFY',
                    ['Event: presence', 'Subscription-State: ' + state],
                    rcontact=rcontact)


def scen_subscribe(enc):
    print('== SUBSCRIBE / NOTIFY / re-SUBSCRIBE / unsubscribe, encoding %s'
          % enc)
    rcli('FLUSHALL')
    px = Proxy('sub_' + enc, th_params(enc, REDIS_URL if enc == 'S' else None))
    sub, ntf = new_pair()
    try:
        d_sub, d_ntf, req, rpl = subscribe_dialog(sub, ntf)
        check('[%s] SUBSCRIBE reaches the notifier and is answered' % enc,
              d_sub is not None)
        if d_sub is None:
            return
        print('     Contact at notifier:  %3d chars  %s'
              % (len(req.contact_uri()), req.contact_uri()))
        print('     Contact at subscriber: %3d chars  %s'
              % (len(rpl.contact_uri()), rpl.contact_uri()))

        s_key, n_key = req.thinfo(), rpl.thinfo()
        nreq, nrpl = notify(d_ntf, sub, 'active;expires=600')
        check('[%s] NOTIFY routed to the real subscriber Contact' % enc,
              nreq is not None and same_target(nreq.ruri, sub.contact) and
              nrpl is not None and nrpl.code == 200,
              nreq and nreq.ruri)
        if enc == 'S':
            # the subscriber's 200 may not shorten a key forked notifier
            # dialogs share
            check('[S] the subscriber state never goes below th_state_ttl',
                  3598 <= ttl(s_key) <= 3600, ttl(s_key))
        rreq, rrpl = transact(d_sub, ntf, 'SUBSCRIBE',
                              ['Event: presence', 'Expires: 600'],
                              rhdrs=['Expires: 600'])
        check('[%s] re-SUBSCRIBE routed to the real notifier Contact' % enc,
              rreq is not None and same_target(rreq.ruri, ntf.contact) and
              rrpl is not None and rrpl.code == 200, rreq and rreq.ruri)

        if enc == 'S':
            check('[S] both legs carry a stored key',
                  KEY_RE.match(s_key or '') and KEY_RE.match(n_key or ''),
                  '%s %s' % (s_key, n_key))
            check('[S] refreshes keep exactly one key per leg',
                  len(th_keys()) == 2 and nreq.thinfo() == n_key and
                  rreq.thinfo() == s_key, th_keys())
            check('[S] notifier TTL = Expires + 30, subscriber th_state_ttl',
                  3598 <= ttl(s_key) <= 3600 and 628 <= ttl(n_key) <= 630,
                  '%d %d' % (ttl(s_key), ttl(n_key)))
            # the reply takes the lifetime of the NOTIFY it answers
            notify(d_ntf, sub, 'active;expires=5000')
            check('[S] a NOTIFY 200 takes the NOTIFY lifetime + 30',
                  5028 <= ttl(s_key) <= 5030, ttl(s_key))

        ureq, urpl = transact(d_sub, ntf, 'SUBSCRIBE',
                              ['Event: presence', 'Expires: 0'],
                              rhdrs=['Expires: 0'])
        if enc == 'S':
            check('[S] the unsubscribe 200 shortens the notifier state',
                  0 < ttl(n_key) <= 60, ttl(n_key))
        freq, frpl = notify(d_ntf, sub, 'terminated;reason=timeout',
                            rcontact=False)
        check('[%s] unsubscribe and final NOTIFY routed' % enc,
              urpl is not None and urpl.code == 200 and frpl is not None and
              frpl.code == 200)
        if enc == 'S':
            check('[S] the final NOTIFY leaves the notifier state short-lived',
                  0 < ttl(n_key) <= 60, ttl(n_key))
            check('[S] the subscriber state stays for forked dialogs',
                  3590 <= ttl(s_key) <= 3600, ttl(s_key))
        check('[%s] proxy logged no ERROR' % enc, not px.lines('ERROR:'),
              px.lines('ERROR:')[:3])
    finally:
        px.stop()
        sub.sock.close()
        ntf.sock.close()


def scen_invite(enc):
    print('== INVITE with and without Session-Expires, encoding %s' % enc)
    rcli('FLUSHALL')
    px = Proxy('inv_' + enc, th_params(enc, REDIS_URL if enc == 'S' else None))
    a, b = new_pair()
    try:
        for se in (1800, None):
            hdrs = ['Supported: timer', 'Session-Expires: %d;refresher=uac'
                    % se] if se else []
            d = Dialog(a, 'sip:%s@127.0.0.1:%d' % (b.name, b.port))
            btag = uuid.uuid4().hex[:10]
            req, rpl = transact(d, b, 'INVITE', hdrs, rhdrs=(
                ['Require: timer', 'Session-Expires: %d;refresher=uac' % se]
                if se else []), peer_tag=btag)
            ok = req is not None and rpl is not None and rpl.code == 200
            check('[%s] INVITE%s answered' % (enc, ' +SE' if se else ''), ok)
            if not ok:
                continue
            print('     Contact at callee: %3d chars  %s'
                  % (len(req.contact_uri()), req.contact_uri()))
            d.rtag, d.target = btag, rpl.contact_uri()
            d.request('ACK', cseq=d.cseq, contact=False)
            ack = b.recv()
            check('[%s] ACK routed to the callee' % enc,
                  ack is not None and ack.method == 'ACK' and
                  same_target(ack.ruri, b.contact), ack and ack.ruri)
            if enc == 'S' and se:
                oreq, orpl = transact(d, b, 'OPTIONS')
                check('[S] in-dialog OPTIONS leaves the call state alone',
                      orpl is not None and orpl.code == 200 and
                      ttl(req.thinfo()) >= 1825 and ttl(rpl.thinfo()) >= 1825,
                      '%d %d' % (ttl(req.thinfo()), ttl(rpl.thinfo())))
            db = Dialog(b, d.luri, callid=d.callid)
            db.ltag, db.rtag, db.luri = btag, d.ltag, d.ruri_aor
            db.target = req.contact_uri()
            breq, brpl = transact(db, a, 'BYE', contact=False)
            check('[%s] BYE from the callee routed to the caller' % enc,
                  breq is not None and same_target(breq.ruri, a.contact) and
                  brpl is not None and brpl.code == 200, breq and breq.ruri)
            if enc != 'S':
                continue
            if se:
                k1, k2 = req.thinfo(), rpl.thinfo()
                check('[S] INVITE with Session-Expires is stored, TTL = SE+30',
                      KEY_RE.match(k1 or '') and KEY_RE.match(k2 or '') and
                      1828 <= ttl(k1) <= 1830 and 1828 <= ttl(k2) <= 1830,
                      '%s %s' % (k1, k2))
            else:
                check('[S] INVITE without session timers stays inline',
                      not KEY_RE.match(req.thinfo() or '') and
                      not KEY_RE.match(rpl.thinfo() or '') and
                      len(th_keys()) == 2, '%s %s' % (req.thinfo(), th_keys()))
        check('[%s] proxy logged no ERROR' % enc, not px.lines('ERROR:'),
              px.lines('ERROR:')[:3])
    finally:
        px.stop()
        a.sock.close()
        b.sock.close()


def scen_miss():
    print('== sequential request after its state expired')
    rcli('FLUSHALL')
    px = Proxy('miss', th_params('S', REDIS_URL))
    sub, ntf = new_pair()
    try:
        d_sub, d_ntf, req, rpl = subscribe_dialog(sub, ntf, expires=1)
        check('[S] short subscription set up', d_sub is not None)
        if d_sub is None:
            return
        # the notifier's state: the subscriber's one lasts th_state_ttl
        key = rpl.thinfo()
        for _ in range(45):
            if ttl(key) == -2:
                break
            time.sleep(1)
        check('[S] the state expired from redis', ttl(key) == -2, ttl(key))
        d_sub.request('SUBSCRIBE', ['Event: presence', 'Expires: 1'])
        r = d_sub.local.recv()
        check('[S] request on an expired state is not matched (404)',
              r is not None and r.code == 404, r and r.first)
        check('[S] the miss is logged as a warning',
              px.lines('no topology hiding state'),
              'no warning line')
        check('[S] the miss is not logged as an error',
              not px.lines('ERROR:'), px.lines('ERROR:')[:3])
    finally:
        px.stop()
        sub.sock.close()
        ntf.sock.close()


def scen_rejected():
    print('== rejected and challenged initial SUBSCRIBE')
    rcli('FLUSHALL')
    px = Proxy('rej', th_params('S', REDIS_URL))
    sub, ntf = new_pair()
    try:
        d = Dialog(sub, 'sip:%s@127.0.0.1:%d' % (ntf.name, ntf.port))
        req, rpl = transact(d, ntf, 'SUBSCRIBE',
                            ['Event: presence', 'Expires: 3600'], code=407,
                            peer_tag=uuid.uuid4().hex[:10])
        key = req.thinfo() if req else None
        check('[S] challenged SUBSCRIBE relayed', rpl is not None and
              rpl.code == 407 and KEY_RE.match(key or ''))
        check('[S] the challenge drops the subscriber state',
              key and ttl(key) == -2, key and ttl(key))
        req, rpl = transact(d, ntf, 'SUBSCRIBE',
                            ['Event: presence', 'Expires: 3600'],
                            rhdrs=['Expires: 3600'],
                            peer_tag=uuid.uuid4().hex[:10])
        check('[S] the retry stores it again under the same key',
              req is not None and req.thinfo() == key and
              3628 <= ttl(key) <= 3630, key and ttl(key))
        d2 = Dialog(sub, 'sip:%s@127.0.0.1:%d' % (ntf.name, ntf.port))
        req, rpl = transact(d2, ntf, 'SUBSCRIBE',
                            ['Event: presence', 'Expires: 3600'], code=489,
                            peer_tag=uuid.uuid4().hex[:10])
        check('[S] a rejected SUBSCRIBE leaves no subscriber state',
              req is not None and rpl is not None and rpl.code == 489 and
              ttl(req.thinfo()) == -2, req and ttl(req.thinfo()))
        check('[S] proxy logged no ERROR', not px.lines('ERROR:'),
              px.lines('ERROR:')[:3])
    finally:
        px.stop()
        sub.sock.close()
        ntf.sock.close()


def scen_options():
    print('== OPTIONS with and without th_state_options')
    bare = 'sip:127.0.0.1:%d' % BASE
    for enc, opt in (('S', None), ('S', 0), ('C', 0)):
        rcli('FLUSHALL')
        extra = [] if opt is None else [('th_state_options', opt)]
        tag = '%s%s' % (enc, '' if opt is None else ',th_state_options=0')
        px = Proxy('opt_%s_%s' % (enc, opt),
                   th_params(enc, REDIS_URL if enc == 'S' else None, extra))
        sub, ntf = new_pair()
        try:
            d = Dialog(sub, 'sip:%s@127.0.0.1:%d' % (ntf.name, ntf.port))
            req, rpl = transact(d, ntf, 'OPTIONS',
                                peer_tag=uuid.uuid4().hex[:10])
            ok = req is not None and rpl is not None and rpl.code == 200
            check('[%s] OPTIONS answered' % tag, ok)
            if not ok:
                continue
            if opt is None:
                check('[%s] OPTIONS state stored for th_state_ttl_short' % tag,
                      KEY_RE.match(req.thinfo() or '') and
                      0 < ttl(req.thinfo()) <= 60, req.thinfo())
            else:
                check('[%s] OPTIONS and its reply carry no state' % tag,
                      req.contact_uri() == bare and
                      rpl.contact_uri() == bare and not th_keys(),
                      '%s %s %s' % (req.contact_uri(), rpl.contact_uri(),
                                    th_keys()))
            check('[%s] proxy logged no ERROR' % tag, not px.lines('ERROR:'),
                  px.lines('ERROR:')[:3])
        finally:
            px.stop()
            sub.sock.close()
            ntf.sock.close()


def scen_mongodb():
    print('== th_state_url on a backend which ignores expiration')
    # cachedb_mongodb is not loaded: the URL is refused before binding
    px = Proxy('mongo', th_params('S', 'mongodb:th://127.0.0.1:27017/th.st'),
               must_start=False)
    try:
        time.sleep(1)
        check('[S] mongodb th_state_url refused at startup',
              not px.alive() and px.lines('ignores the expiration'),
              ''.join(px.lines('ERROR:')[:2]).strip())
    finally:
        px.stop()


def scen_switch():
    print('== switching C -> S -> C in place keeps in-flight dialogs')
    rcli('FLUSHALL')
    sub, ntf = new_pair()
    px = Proxy('sw_c', th_params('C'))
    try:
        d1_sub, d1_ntf, req, rpl = subscribe_dialog(sub, ntf, expires=3600)
    finally:
        px.stop()
    px = Proxy('sw_s', th_params('S', REDIS_URL))
    try:
        nreq, nrpl = notify(d1_ntf, sub, 'active;expires=3600')
        check('[C->S] in-flight compact dialog still routed',
              nreq is not None and same_target(nreq.ruri, sub.contact) and
              nrpl is not None and nrpl.code == 200)
        check('[C->S] and it stays inline',
              nreq is not None and nreq.thinfo() and
              not KEY_RE.match(nreq.thinfo()), nreq and nreq.thinfo())
        d2_sub, d2_ntf, req2, rpl2 = subscribe_dialog(sub, ntf, expires=3600)
        check('[C->S] a new dialog gets stored keys',
              req2 is not None and KEY_RE.match(req2.thinfo() or ''))
    finally:
        px.stop()
    px = Proxy('sw_back', th_params('C', REDIS_URL))
    try:
        if d2_ntf is not None:
            nreq, nrpl = notify(d2_ntf, sub, 'active;expires=3600')
            check('[S->C] stored dialog still routed while th_state_url is set',
                  nreq is not None and same_target(nreq.ruri, sub.contact) and
                  nrpl is not None and nrpl.code == 200)
            check('[S->C] and its Contact goes back inline',
                  nreq is not None and nreq.thinfo() and
                  not KEY_RE.match(nreq.thinfo()))
    finally:
        px.stop()
        sub.sock.close()
        ntf.sock.close()


def scen_storedown():
    print('== th_state_url going down under a running proxy')
    port = BASE + 5
    redis = redis_start(port)
    px = Proxy('down', th_params('S', 'redis:th://127.0.0.1:%d/' % port))
    a, b = new_pair()
    try:
        d_sub, d_ntf, req, rpl = subscribe_dialog(a, b)
        check('[S] stored while the store is up',
              d_sub is not None and KEY_RE.match(req.thinfo() or ''))
        redis.terminate()
        redis.wait()
        se = ['Supported: timer', 'Session-Expires: 1800;refresher=uac']
        for n in range(3):
            d = Dialog(a, 'sip:%s@127.0.0.1:%d' % (b.name, b.port))
            btag = uuid.uuid4().hex[:10]
            req, rpl = transact(d, b, 'INVITE', se, rhdrs=se, peer_tag=btag)
            ok = req is not None and rpl is not None and rpl.code == 200
            check('[S] INVITE %d answered with the store down' % n, ok)
            if not ok:
                continue
            check('[S] INVITE %d: both Contacts hidden, state inline' % n,
                  req.thinfo() and not KEY_RE.match(req.thinfo()) and
                  rpl.thinfo() and not KEY_RE.match(rpl.thinfo()),
                  '%s / %s' % (req.contact_uri(), rpl.contact_uri()))
            d.rtag, d.target = btag, rpl.contact_uri()
            db = Dialog(b, d.luri, callid=d.callid)
            db.ltag, db.rtag, db.luri = btag, d.ltag, d.ruri_aor
            db.target = req.contact_uri()
            breq, brpl = transact(db, a, 'BYE', contact=False)
            check('[S] INVITE %d: BYE routed to the caller' % n,
                  breq is not None and same_target(breq.ruri, a.contact) and
                  brpl is not None and brpl.code == 200, breq and breq.ruri)
        warns = px.lines('travel inline')
        # rate limited per worker, and the proxy runs 2 of them
        check('[S] the failed writes are warned about once per worker',
              1 <= len(warns) <= 2, '%d lines' % len(warns))
        check('[S] proxy still running', px.alive())
    finally:
        px.stop()
        if redis.poll() is None:
            redis.terminate()
            redis.wait()
        a.sock.close()
        b.sock.close()


def scen_ttlcap():
    print('== lifetimes from the far end are bounded by th_state_ttl_max')
    rcli('FLUSHALL')
    px = Proxy('cap', th_params('S', REDIS_URL))
    a, b = new_pair()
    try:
        d_sub, d_ntf, req, rpl = subscribe_dialog(a, b, expires=2000000000)
        key = req and req.thinfo()
        check('[S] SUBSCRIBE Expires: 2000000000 kept for th_state_ttl_max',
              key and KEY_RE.match(key) and 86390 <= ttl(key) <= 86400,
              key and ttl(key))
        d = Dialog(a, 'sip:%s@127.0.0.1:%d' % (b.name, b.port))
        se = ['Supported: timer', 'Session-Expires: 2147483640;refresher=uac']
        req, rpl = transact(d, b, 'INVITE', se, rhdrs=se,
                            peer_tag=uuid.uuid4().hex[:10])
        key = req and req.thinfo()
        check('[S] Session-Expires: 2147483640 kept for th_state_ttl_max',
              key and KEY_RE.match(key) and 86390 <= ttl(key) <= 86400,
              key and ttl(key))
    finally:
        px.stop()
        a.sock.close()
        b.sock.close()
    px = Proxy('cap_bad', th_params('S', REDIS_URL,
                                    [('th_state_ttl_max', 2592001)]),
               must_start=False)
    check('[S] th_state_ttl_max over 30 days is refused at startup',
          not px.alive())
    px.stop()


def scen_expires():
    print('== where a lifetime is read from: REGISTER vs SUBSCRIBE')
    rcli('FLUSHALL')
    px = Proxy('exp', th_params('S', REDIS_URL))
    a, b = new_pair()
    try:
        d_sub, d_ntf, req, rpl = subscribe_dialog(a, b)
        n_key = rpl and rpl.thinfo()
        check('[S] subscription set up', d_sub is not None and n_key)
        if d_sub is None:
            return
        rreq, rrpl = transact(d_sub, b, 'SUBSCRIBE', [
            'Contact: <%s>;expires=0' % a.contact, 'Event: presence',
            'Expires: 600'], rhdrs=['Expires: 600'], contact=False)
        check('[S] a Contact ;expires=0 does not end a SUBSCRIBE refresh',
              rrpl is not None and rrpl.code == 200 and ttl(n_key) >= 590,
              ttl(n_key))
        d = Dialog(a, 'sip:%s@127.0.0.1:%d' % (b.name, b.port))
        req, rpl = transact(d, b, 'REGISTER', ['Expires: 7200'],
                            rhdrs=['Expires: 7200'])
        key = req and req.thinfo()
        check('[S] REGISTER kept for its Expires plus 30 s',
              key and KEY_RE.match(key) and 7225 <= ttl(key) <= 7230,
              key and ttl(key))
    finally:
        px.stop()
        a.sock.close()
        b.sock.close()


def scen_keys():
    print('== a key only serves the dialog it was made for')
    rcli('FLUSHALL')
    px = Proxy('keys', th_params('S', REDIS_URL))
    a, b = new_pair()
    c = UA('evil', BASE + 4, 'evil')
    try:
        d_sub, d_ntf, req, rpl = subscribe_dialog(a, b)
        k_sub = req and req.thinfo()
        check('[S] subscription set up', d_sub is not None and k_sub)
        if d_sub is None:
            return
        # the notifier reuses the subscriber key in another dialog
        fake = Dialog(b, d_ntf.ruri_aor)
        fake.ltag, fake.rtag, fake.luri = d_ntf.ltag, d_ntf.rtag, d_ntf.luri
        fake.target = d_ntf.target
        fake.request('NOTIFY', ['Event: presence',
                                'Subscription-State: active;expires=600'])
        r = b.recv()
        check('[S] a key used under another Call-ID is not routed',
              r is not None and r.code == 404, r and r.first)
        # a call-id and tag split elsewhere must not hash to the same key
        x = d_sub.callid
        ev = Dialog(c, 'sip:%s@127.0.0.1:%d' % (b.name, b.port),
                    callid=x[:-4])
        ev.ltag = x[-4:] + d_sub.ltag
        ereq, erpl = transact(ev, b, 'SUBSCRIBE',
                              ['Event: presence', 'Expires: 600'],
                              rhdrs=['Expires: 600'],
                              peer_tag=uuid.uuid4().hex[:10])
        check('[S] a shifted Call-ID/tag gets a key of its own',
              ereq is not None and ereq.thinfo() != k_sub,
              ereq and ereq.thinfo())
        nreq, nrpl = notify(d_ntf, a, 'active;expires=600')
        check('[S] the subscriber still gets its NOTIFY',
              nreq is not None and same_target(nreq.ruri, a.contact),
              nreq and nreq.ruri)
        # a reply carrying its caller's tag as To tag
        d = Dialog(a, 'sip:%s@127.0.0.1:%d' % (b.name, b.port))
        se = ['Supported: timer', 'Session-Expires: 1800;refresher=uac']
        req, rpl = transact(d, b, 'INVITE', se, rhdrs=se, peer_tag=d.ltag)
        check('[S] a reply tagged as its caller is not stored',
              rpl is not None and rpl.thinfo() and
              not KEY_RE.match(rpl.thinfo()) and
              KEY_RE.match(req.thinfo() or ''),
              rpl and rpl.thinfo())
    finally:
        px.stop()
        a.sock.close()
        b.sock.close()
        c.sock.close()


def scen_teardown():
    print('== ending a subscription: retransmission, challenge, forks')
    rcli('FLUSHALL')
    px = Proxy('tear', th_params('S', REDIS_URL))
    a, b = new_pair()
    n2 = UA('ntf2', BASE + 4, 'presence-server-2')
    try:
        d_sub, d_ntf, req, rpl = subscribe_dialog(a, b)
        check('[S] subscription set up', d_sub is not None)
        if d_sub is None:
            return
        # a second notifier dialog of the same (forked) SUBSCRIBE
        d_n2 = Dialog(n2, d_ntf.ruri_aor, callid=d_sub.callid)
        d_n2.ltag, d_n2.rtag = uuid.uuid4().hex[:10], d_sub.ltag
        d_n2.luri, d_n2.target = d_ntf.luri, d_ntf.target
        r2, p2 = notify(d_n2, a, 'active;expires=3600')
        check('[S] the forked notifier reaches the subscriber',
              r2 is not None and p2 is not None and p2.code == 200)
        # the first notifier ends its dialog, its NOTIFY is retransmitted
        d_ntf.request('NOTIFY', ['Event: presence',
                                 'Subscription-State: terminated'])
        nreq = a.recv()
        b.send(b.last)
        time.sleep(0.3)
        if nreq is not None:
            reply(a, nreq, 200, contact=False)
        r = b.recv()
        check('[S] a retransmitted final NOTIFY is not answered 404',
              r is not None and r.code == 200, r and r.first)
        r2, p2 = notify(d_n2, a, 'active;expires=3600')
        check('[S] the forked dialog survives the other one ending',
              r2 is not None and same_target(r2.ruri, a.contact), r2)
        # a challenged unsubscribe, then its authenticated retry
        ureq, urpl = transact(d_sub, b, 'SUBSCRIBE',
                              ['Event: presence', 'Expires: 0'], code=407)
        rreq, rrpl = transact(d_sub, b, 'SUBSCRIBE',
                              ['Event: presence', 'Expires: 0',
                               'Proxy-Authorization: Digest x'],
                              rhdrs=['Expires: 0'])
        check('[S] the retry of a challenged unsubscribe is routed',
              urpl is not None and urpl.code == 407 and rreq is not None and
              rrpl is not None and rrpl.code == 200, rreq and rreq.first)
    finally:
        px.stop()
        a.sock.close()
        b.sock.close()
        n2.sock.close()


def call_dialog(a, b, se=1800):
    """INVITE (with Session-Expires if @se) answered by b; ACKed."""
    hdrs = ['Supported: timer', 'Session-Expires: %d;refresher=uac' % se] \
        if se else []
    d = Dialog(a, 'sip:%s@127.0.0.1:%d' % (b.name, b.port))
    btag = uuid.uuid4().hex[:10]
    req, rpl = transact(d, b, 'INVITE', hdrs, rhdrs=hdrs, peer_tag=btag)
    if not req or not rpl or rpl.code != 200:
        return None, None, req, rpl
    d.rtag, d.target = btag, rpl.contact_uri()
    d.request('ACK', cseq=d.cseq, contact=False)
    b.recv()
    db = Dialog(b, d.luri, callid=d.callid)
    db.ltag, db.rtag, db.luri = btag, d.ltag, d.ruri_aor
    db.target = req.contact_uri()
    return d, db, req, rpl


def scen_calldlg():
    print('== other usages inside an INVITE dialog leave its state alone')
    for se in (1800, None):
        tag = '[S%s]' % (' +SE' if se else ' no SE')
        rcli('FLUSHALL')
        px = Proxy('calldlg_%s' % se, th_params('S', REDIS_URL))
        a, b = new_pair()
        try:
            d, db, req, rpl = call_dialog(a, b, se)
            check('%s call set up' % tag, d is not None)
            if d is None:
                continue
            keys = th_keys()
            ka, kb = req.thinfo(), rpl.thinfo()
            # B transfers A: REFER, 202, NOTIFYs active then terminated
            rreq, rrpl = transact(db, a, 'REFER',
                                  ['Refer-To: <sip:c@127.0.0.1>'], code=202)
            nreq, nrpl = transact(d, b, 'NOTIFY', [
                'Event: refer', 'Subscription-State: active;expires=60'])
            treq, trpl = transact(d, b, 'NOTIFY', [
                'Event: refer', 'Subscription-State: terminated'])
            check('%s REFER and NOTIFYs routed' % tag,
                  rrpl is not None and nrpl is not None and trpl is not None)
            inl = [m.thinfo() for m in (rrpl, nreq, nrpl, treq, trpl) if m]
            check('%s they travel inline' % tag,
                  len(inl) == 5 and all(t and not KEY_RE.match(t) for t in inl),
                  inl)
            check('%s and store nothing' % tag, th_keys() == keys,
                  '%s -> %s' % (keys, th_keys()))
            if se:
                check('%s the call states keep their lifetime' % tag,
                      ttl(ka) >= 1800 and ttl(kb) >= 1800,
                      '%d %d' % (ttl(ka), ttl(kb)))
                # a session refresh: the request and its 2xx store again
                se9 = ['Supported: timer', 'Session-Expires: 900;refresher=uac']
                ireq, irpl = transact(d, b, 'INVITE', se9, rhdrs=se9)
                check('%s a re-INVITE with SE 900 sets both lifetimes' % tag,
                      irpl is not None and ireq.thinfo() == ka and
                      irpl.thinfo() == kb and 925 <= ttl(ka) <= 930 and
                      925 <= ttl(kb) <= 930,
                      '%d %d' % (ttl(ka), ttl(kb)))
                d.request('ACK', cseq=d.cseq, contact=False)
                b.recv()
                # a re-INVITE without session timers
                ireq, irpl = transact(d, b, 'INVITE')
                check('%s a re-INVITE without SE goes inline' % tag,
                      ireq is not None and ireq.thinfo() and
                      not KEY_RE.match(ireq.thinfo()) and ttl(ka) <= 930,
                      '%s %d' % (ireq and ireq.thinfo(), ttl(ka)))
                d.request('ACK', cseq=d.cseq, contact=False)
                b.recv()
            breq, brpl = transact(db, a, 'BYE', contact=False)
            check('%s BYE still routed to the caller' % tag,
                  breq is not None and same_target(breq.ruri, a.contact),
                  breq and breq.ruri)
        finally:
            px.stop()
            a.sock.close()
            b.sock.close()


def scen_answer():
    print('== the answer of a stored INVITE sets the caller lifetime')
    rcli('FLUSHALL')
    px = Proxy('answer', th_params('S', REDIS_URL))
    a, b = new_pair()
    try:
        for rse, lo, hi in ((None, 3590, 3600), (900, 925, 930)):
            se = ['Supported: timer', 'Session-Expires: 1800;refresher=uac']
            d = Dialog(a, 'sip:%s@127.0.0.1:%d' % (b.name, b.port))
            rh = ['Require: timer', 'Session-Expires: %d;refresher=uac' % rse] \
                if rse else []
            req, rpl = transact(d, b, 'INVITE', se, rhdrs=rh,
                                peer_tag=uuid.uuid4().hex[:10])
            ka = req and req.thinfo()
            what = 'with Session-Expires %d' % rse if rse else 'without timers'
            check('[S] answered %s: caller kept %d..%d s' % (what, lo, hi),
                  ka and KEY_RE.match(ka) and lo <= ttl(ka) <= hi,
                  ka and ttl(ka))
    finally:
        px.stop()
        a.sock.close()
        b.sock.close()


def scen_spiral():
    print('== a request hidden twice (spiral) keeps the first state')
    rcli('FLUSHALL')
    px = Proxy('spiral', th_params('S', REDIS_URL))
    a, b = new_pair()
    c = UA('far', BASE + 4, 'far')
    try:
        se = ['Supported: timer', 'Session-Expires: 1800;refresher=uac']
        d = Dialog(a, 'sip:%s@127.0.0.1:%d' % (b.name, b.port))
        d.request('INVITE', se)
        req = b.recv()
        k = req and req.thinfo()
        check('[S] first pass stores the caller', k and KEY_RE.match(k), k)
        if not k:
            return
        # b sends it on through the proxy again, Contact as it got it
        d2 = Dialog(b, 'sip:%s@127.0.0.1:%d' % (c.name, c.port),
                    callid=d.callid)
        d2.ltag, d2.luri = d.ltag, d.luri
        d2.request('INVITE', se + ['Contact: <%s>' % req.contact_uri()],
                   contact=False)
        req2 = c.recv()
        check('[S] the second pass nests its state inline',
              req2 is not None and req2.thinfo() and
              not KEY_RE.match(req2.thinfo()), req2 and req2.thinfo())
        check('[S] the first state still holds the real Contact',
              a.contact.split(';')[0] in rcli('GET', 'th:' + k[1:]),
              rcli('GET', 'th:' + k[1:]))
    finally:
        px.stop()
        a.sock.close()
        b.sock.close()
        c.sock.close()


def scen_decoded():
    print('== $TH_decoded_* are set for a stored dialog')
    rcli('FLUSHALL')
    px = Proxy('decoded', th_params('S', REDIS_URL))
    a, b = new_pair()
    try:
        d_sub, d_ntf, req, rpl = subscribe_dialog(a, b)
        check('[S] subscription set up', d_sub is not None)
        if d_sub is None:
            return
        notify(d_ntf, a, 'active;expires=600')
        got = px.lines('decoded <')
        check('[S] $TH_decoded_contact is the real Contact',
              got and a.contact.split(';')[0] in got[-1] and
              'routes 0' in got[-1], got[-1:])
        # garbage under a key: no crash, a clean 404
        rcli('SET', 'th:' + req.thinfo()[1:], 'garbage', 'EX', '600')
        d_ntf.request('NOTIFY', ['Event: presence',
                                 'Subscription-State: active;expires=600'])
        r = b.recv()
        check('[S] a malformed stored state gives 404',
              r is not None and r.code == 404 and px.alive(), r and r.first)
    finally:
        px.stop()
        a.sock.close()
        b.sock.close()


def scen_badct():
    print('== a bad Contact is refused once, not retried inline')
    rcli('FLUSHALL')
    px = Proxy('badct', th_params('S', REDIS_URL))
    a, b = new_pair()
    try:
        d = Dialog(a, 'sip:%s@127.0.0.1:%d' % (b.name, b.port))
        d.request('SUBSCRIBE', ['Contact: <%s>, <sip:x@127.0.0.1>' % a.contact,
                                'Event: presence', 'Expires: 600'],
                  contact=False)
        b.recv()
        time.sleep(0.3)
        bad = px.lines('bad Contact HDR')
        check('[S] the bad Contact is logged once', len(bad) == 1,
              '%d lines' % len(bad))
        check('[S] nothing is stored for it', not th_keys(), th_keys())
    finally:
        px.stop()
        a.sock.close()
        b.sock.close()


def scen_backend():
    print('== empty th_state_url; a stored dialog while the store is down')
    px = Proxy('url_empty', th_params('C', '', []))
    check('[C] th_state_url "" means no storage', px.alive(),
          px.lines('ERROR:')[-2:])
    px.stop()
    port = BASE + 5
    redis = redis_start(port)
    px = Proxy('down2', th_params('S', 'redis:th://127.0.0.1:%d/' % port))
    a, b = new_pair()
    try:
        d_sub, d_ntf, req, rpl = subscribe_dialog(a, b)
        check('[S] stored while the store is up',
              d_sub is not None and KEY_RE.match(req.thinfo() or ''))
        if d_sub is None:
            return
        redis.terminate()
        redis.wait()
        d_ntf.request('NOTIFY', ['Event: presence',
                                 'Subscription-State: active;expires=600'])
        r = b.recv()
        check('[S] a stored dialog cannot be routed while the store is down',
              r is not None and r.code == 404 and px.alive(), r and r.first)
        redis = redis_start(port)
        time.sleep(6)
        d2, n2, req2, rpl2 = subscribe_dialog(a, b)
        k2 = req2 and req2.thinfo()
        check('[S] storing resumes once the store is back',
              k2 and KEY_RE.match(k2) and
              rcli('EXISTS', 'th:' + k2[1:], port=port) == '1', k2)
    finally:
        px.stop()
        if redis.poll() is None:
            redis.terminate()
            redis.wait()
        a.sock.close()
        b.sock.close()


def scen_local408():
    print('== an unanswered initial SUBSCRIBE leaves no state (local 408)')
    rcli('FLUSHALL')
    px = Proxy('l408', th_params('S', REDIS_URL))
    a, b = new_pair()
    try:
        d = Dialog(a, 'sip:%s@127.0.0.1:%d' % (b.name, b.port))
        d.request('SUBSCRIBE', ['Event: presence', 'Expires: 3600'])
        req = b.recv()
        key = req and req.thinfo()
        a.sock.settimeout(6)
        r = a.recv()
        a.sock.settimeout(3)
        check('[S] the proxy answers 408 itself',
              r is not None and r.code == 408, r and r.first)
        check('[S] the subscriber state is dropped',
              key and KEY_RE.match(key) and ttl(key) == -2, key and ttl(key))
    finally:
        px.stop()
        a.sock.close()
        b.sock.close()


def scen_compact():
    scen_subscribe('C')
    scen_invite('C')


SCENARIOS = {
    'compact': scen_compact,
    'subscribe': lambda: scen_subscribe('S'),
    'invite': lambda: scen_invite('S'),
    'rejected': scen_rejected,
    'options': scen_options,
    'mongodb': scen_mongodb,
    'switch': scen_switch,
    'miss': scen_miss,
    'storedown': scen_storedown,
    'ttlcap': scen_ttlcap,
    'expires': scen_expires,
    'keys': scen_keys,
    'teardown': scen_teardown,
    'calldlg': scen_calldlg,
    'answer': scen_answer,
    'spiral': scen_spiral,
    'decoded': scen_decoded,
    'badct': scen_badct,
    'backend': scen_backend,
    'local408': scen_local408,
}


def main(argv):
    dump = None
    if argv[:1] == ['--dump']:
        dump, argv = argv[1], argv[2:]
    names = argv or list(SCENARIOS)
    redis = redis_start()
    try:
        for n in names:
            SCENARIOS[n]()
    finally:
        redis.terminate()
        redis.wait()
    if dump:
        with open(dump, 'w') as f:
            f.write('\n'.join(contacts_seen) + '\n')
    failed = [d for d, ok in results if not ok]
    print('%d checks, %d failed' % (len(results), len(failed)))
    if failed or not results:
        print('logs kept in %s' % work)
        return 1
    if not os.environ.get('TH_TEST_DIR'):
        shutil.rmtree(work)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
