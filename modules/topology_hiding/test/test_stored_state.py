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
#   PORT_BASE     first of the 4 UDP/TCP ports used (default: 25060)
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
work = tempfile.mkdtemp(prefix='th_stored.')


def check(desc, ok, detail=''):
    results.append((desc, bool(ok)))
    print('  %s: %s%s' % ('PASS' if ok else 'FAIL', desc,
                          '' if ok else ' (%s)' % detail))


# --- redis ---------------------------------------------------------------

def rcli(*args):
    out = subprocess.run([REDIS_CLI, '-h', '127.0.0.1', '-p', str(REDIS_PORT)]
                         + list(args), capture_output=True, text=True)
    return out.stdout.strip()


def redis_start():
    p = subprocess.Popen([REDIS_SERVER, '--bind', '127.0.0.1', '--port',
                          str(REDIS_PORT), '--save', '', '--appendonly', 'no',
                          '--dir', work], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
    for _ in range(50):
        if rcli('PING') == 'PONG':
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
%(params)s

route {
	if (!mf_process_maxfwd_header(10)) {
		sl_send_reply(483, "Too Many Hops");
		exit;
	}
	if (has_totag()) {
		if (topology_hiding_match()) {
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
    if url:
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
            # the 200 OK says nothing of the lifetime, its NOTIFY does
            check('[S] a reply takes its TTL from its request',
                  628 <= ttl(s_key) <= 630, ttl(s_key))
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
            check('[S] TTL = Expires + 30 on both legs',
                  628 <= ttl(s_key) <= 630 and 628 <= ttl(n_key) <= 630,
                  '%d %d' % (ttl(s_key), ttl(n_key)))
            # the 200 carries no Contact: only the refresh in place moves it
            notify(d_ntf, sub, 'active;expires=3000', rcontact=False)
            check('[S] a NOTIFY refreshes the state it was routed by',
                  3028 <= ttl(s_key) <= 3030, ttl(s_key))

        ureq, urpl = transact(d_sub, ntf, 'SUBSCRIBE',
                              ['Event: presence', 'Expires: 0'],
                              rhdrs=['Expires: 0'])
        freq, frpl = notify(d_ntf, sub, 'terminated;reason=timeout',
                            rcontact=False)
        check('[%s] unsubscribe and final NOTIFY routed' % enc,
              urpl is not None and urpl.code == 200 and frpl is not None and
              frpl.code == 200)
        if enc == 'S':
            check('[S] the final NOTIFY drops the state it was routed by',
                  ttl(s_key) == -2, ttl(s_key))
            check('[S] what is left after teardown is short-lived',
                  0 < ttl(n_key) <= 60 and len(th_keys()) == 1, th_keys())
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
        key = req.thinfo()
        for _ in range(45):
            if ttl(key) == -2:
                break
            time.sleep(1)
        check('[S] the state expired from redis', ttl(key) == -2, ttl(key))
        d_ntf.request('NOTIFY', ['Event: presence',
                                 'Subscription-State: active;expires=1'])
        r = d_ntf.local.recv()
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
    shutil.rmtree(work)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
