#!/usr/bin/env python3
"""A second implementation of the wire-level-2 constructions, for cross-checking.

Recomputes the golden vectors of mr.enzo 1.1 (docs/native/vectors/*V11.json, pqxdhV1.json,
mlkem768Kat.json, pttV1.json, reactGroupV1.json, stickerV1.json, pushHintV1.json,
meshCourierV1.json) from the formulas WRITTEN IN THE DOCUMENTS (wire-1.1.md — not published —,
docs/native/protocol/03-crypto.md, 04-mesh.md) with other libraries than the Rust core uses:
libsodium (PyNaCl), Python's hashlib / hmac, and OpenSSL's own ML-KEM-768.

It shares no code with native/core, so an agreement means the documents say what the code does.
Not part of CI (OpenSSL >= 3.5 and PyNaCl are not build dependencies). Run by hand after a
change to a level-2 construction (it needs PyNaCl and OpenSSL >= 3.5):

    OPENSSL=/path/to/openssl python3 native/core/tests/independent_check.py

Exit status 0 = every check agrees.
"""
import base64, hashlib, hmac, json, os, shutil, struct, subprocess, sys, tempfile, zlib

try:
    import nacl.bindings as nb
    from nacl.signing import SigningKey, VerifyKey
except ImportError:
    sys.exit("PyNaCl is required")

V = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "docs", "native", "vectors") + os.sep
O = os.environ.get("OPENSSL") or shutil.which("openssl") or "openssl"
try:
    _ver = subprocess.run([O, "list", "-kem-algorithms"], capture_output=True, text=True).stdout
except OSError:
    _ver = ""
if "ML-KEM-768" not in _ver:
    sys.exit(f"{O} has no ML-KEM-768 (OpenSSL >= 3.5 is needed; set OPENSSL=/path/to/openssl)")
os.chdir(tempfile.mkdtemp(prefix="mrenzo-indep-"))

b64=lambda b: base64.b64encode(b).decode()
d64=lambda s: base64.b64decode(s, validate=True)
sha=lambda b: hashlib.sha256(b).digest()
def hkdf(ikm, info, n=32, salt=b'\0'*32):
    """HKDF-SHA256 with the 32-byte zero salt (03 notation)."""
    prk=hmac.new(salt, ikm, hashlib.sha256).digest()
    out=b''; t=b''; i=1
    while len(out)<n:
        t=hmac.new(prk, t+info+bytes([i]), hashlib.sha256).digest(); out+=t; i+=1
    return out[:n]
be64=lambda x: struct.pack('>Q',x)
def ed_ok(pub, msg, sig):
    try: VerifyKey(pub).verify(msg, sig); return True
    except Exception: return False
checks=[]
def ck(name, cond):
    checks.append((name, bool(cond)))
    if not cond: print('MISMATCH:', name)
def load(f): return json.load(open(V+f))

def decap(seedhex, ct):
    subprocess.run([O,'genpkey','-algorithm','ML-KEM-768','-pkeyopt','hexseed:'+seedhex,'-out','t.pem'],check=True,capture_output=True)
    open('t.ct','wb').write(ct)
    subprocess.run([O,'pkeyutl','-decap','-inkey','t.pem','-in','t.ct','-secret','t.ss'],check=True,capture_output=True)
    spki=subprocess.run([O,'pkey','-in','t.pem','-pubout','-outform','DER'],check=True,capture_output=True).stdout
    return open('t.ss','rb').read(), spki[-1184:]

# ───────────── 0. ML-KEM-768 known answers (wire-1.1 §W6.7) ─────────────
kat=load('mlkem768Kat.json')
for i,c in enumerate(kat['cases']):
    ss,ek=decap(c['seedHex'], d64(c['ctB64']))
    ck(f'kat {i}: ek = KeyGen(seed)', b64(ek)==c['ekB64'] and sha(ek).hex()==c['ekSha256Hex'])
    ck(f'kat {i}: Decaps(ct) = ss', ss.hex()==c['ssHex'])
    ck(f'kat {i}: implicit rejection', decap(c['seedHex'], d64(c['rejectCtB64']))[0].hex()==c['rejectSsHex'])
    subprocess.run([O,'pkey','-in','t.pem','-pubout','-out','t.pub'],check=True,capture_output=True)
    subprocess.run([O,'pkeyutl','-encap','-pubin','-inkey','t.pub','-pkeyopt','hexikme:'+c['mHex'],'-out','t.ct2','-secret','t.ss2'],check=True,capture_output=True)
    ck(f'kat {i}: Encaps(ek, m) = (ct, ss)', open('t.ct2','rb').read()==d64(c['ctB64']) and open('t.ss2','rb').read().hex()==c['ssHex'])

# ───────────── A. hybrid session setup (wire-1.1 §W6.1–§W6.3) ─────────────
p=load('pqxdhV1.json'); x=load('x3dhV2.json')
A,B=p['keys']['alice'],p['keys']['bob']
spk,opk=x['bobPrekeys']['spk'],x['bobPrekeys']['opk']
kem={42:p['bobKemPrekeys']['oneTime'],7:p['bobKemPrekeys']['lastResort']}
for kid,k in kem.items():
    seed=k['seedHex'][:128]
    ek=d64(k['pubB64'])
    kind=bytes([1 if k['kind']=='lastResort' else 2])
    signed=b'mrenzo-kem-prekey-v1'+be64(k['keyId'])+kind+b'\x0a'+ek
    ck(f'kem prekey {kid}: signed bytes hash', sha(signed).hex()==k['signedBytesSha256Hex'])
    ck(f'kem prekey {kid}: Ed25519 signature under the identity key', ed_ok(d64(B['ed25519PubB64']), signed, d64(k['signatureB64'])))
    ss,ek2=decap(seed, b'\0'*1088)
    ck(f'kem prekey {kid}: ek = KeyGen(seed) per OpenSSL', ek2==ek and sha(ek).hex()==k['pubSha256Hex'])
    ck(f'kem prekey {kid}: upload entry shape', json.loads(k['uploadEntry'])=={"keyId":k['keyId'],"alg":"mlkem768","pubKey":k['pubB64'],"signature":k['signatureB64']})
for name,c in p['cases'].items():
    k=kem[c['kemKeyId']]; ek=d64(k['pubB64']); ct=d64(c['kemCtB64'])
    ss,_=decap(k['seedHex'][:128], ct)
    ekp=d64(c['ekPrivB64'])
    dh=lambda priv,pub: nb.crypto_scalarmult(priv,pub)
    dhs=dh(d64(A['x25519PrivB64']),d64(spk['pubB64']))+dh(ekp,d64(B['x25519PubB64']))+dh(ekp,d64(spk['pubB64']))
    if c['withOpk']: dhs+=dh(ekp,d64(opk['pubB64']))
    kind=bytes([1 if k['kind']=='lastResort' else 2])
    info=b'mrenzo-pqxdh-v1'+b'\x0a'+kind+be64(k['keyId'])+sha(ek)+sha(ct)
    ck(f'{name}: info is 89 bytes', len(info)==89)
    sk=hkdf(b'\xff'*32+dhs+ss, info)
    ck(f'{name}: SK', b64(sk)==c['secret']['skB64'])
    ck(f'{name}: classical SK differs', hkdf(b'\xff'*32+dhs, b'mrenzo-x3dh-v2')!=sk and c['classicalSkB64']!=c['secret']['skB64'])
    ad=b'mrenzo-ad-v3'+d64(A['x25519PubB64'])+d64(A['ed25519PubB64'])+d64(B['x25519PubB64'])+d64(B['ed25519PubB64'])
    ck(f'{name}: AD (140 bytes)', b64(ad)==c['secret']['adB64'] and len(ad)==140)
    ck(f'{name}: sid', b64(hkdf(sk,b'mrenzo-ratchet-session-id-v3'))==c['secret']['sidB64'])
    ck(f'{name}: RK0', b64(hkdf(sk,b'mrenzo-ratchet-init-v3'))==c['secret']['rk0B64'])
    w=json.loads(c['message']['wire']); xh=w['x']
    ck(f'{name}: kem is the last key of x', list(xh.keys())[-1]=='kem' and xh['kem']['id']==k['keyId'] and d64(xh['kem']['ct'])==ct)
    hdr=b'\x03'+d64(w['dh'])+be64(w['pn'])+be64(w['n'])+b'\x02'+d64(xh['ik'])+d64(xh['ed'])+d64(xh['ek'])+be64(xh['spk'])+be64(xh['opk'] if 'opk' in xh and xh['opk'] is not None else 2**64-1)+be64(xh['kem']['id'])+ct
    ck(f'{name}: header bytes (xflag 2)', len(hdr)==c['message']['headerLen'] and sha(hdr).hex()==c['message']['headerSha256Hex'])
    # The first message (03 §V3.3.2–§V3.3.3): (root, CKs) = KDF_RK(RK0, DH3); (CK', mk) = KDF_CK(CKs);
    # (k_enc, k_mac) = HKDF(mk, "mrenzo-ratchet-msg-keys-v3", 64); mac = HMAC(k_mac, AD ‖ hdr ‖ ct).
    dh3=dh(ekp,d64(spk['pubB64']))
    cks=hkdf(hkdf(sk,b'mrenzo-ratchet-init-v3')+dh3, b'mrenzo-ratchet-step-v1', 64)[32:]
    mk=hkdf(cks,b'mrenzo-ratchet-msg-v1')
    kk=hkdf(mk,b'mrenzo-ratchet-msg-keys-v3',64); ctb=d64(w['ct'])
    mac=hmac.new(kk[32:], ad+hdr+ctb, hashlib.sha256).digest()
    ck(f'{name}: MAC over AD ‖ header (flag, kem id, kem ct) ‖ ct', b64(mac)==w['mac']==c['message']['macB64'])
    try: body=nb.crypto_secretbox_open(ctb[24:],ctb[:24],kk[:32]).decode()
    except Exception: body=None
    ck(f'{name}: the first message decrypts', body==c['message']['plaintext'])
    stripped=b'\x03'+d64(w['dh'])+be64(w['pn'])+be64(w['n'])+b'\x01'+hdr[50:50+112]
    ck(f'{name}: the MAC does not verify for the header without kem', hmac.new(kk[32:], ad+stripped+ctb, hashlib.sha256).digest()!=mac and len(stripped)==1258-1096)

# ───────────── B. caps statement (§W4.2) ─────────────
c=load('capsV11.json'); st=json.loads(c['statement']['json'])
canon=f"mrenzo-caps-v1|{st['uid']}|{st['caps']['v']}|{','.join(st['caps'].get('f',[]))}|{st['ts']}"
ck('caps: canonical string', canon==c['statement']['canonical'])
ck('caps: signature', ed_ok(d64(c['keys']['alice']['ed25519PubB64']), canon.encode(), d64(st['sig'])))
for case in c['cases']:
    try:
        s=json.loads(case['statement']); cn=f"mrenzo-caps-v1|{s['uid']}|{s['caps']['v']}|{','.join(s['caps'].get('f',[]))}|{s['ts']}"
        sig_ok=ed_ok(d64(case['pinnedEdB64']), cn.encode(), d64(s['sig']))
    except Exception: sig_ok=False
    if case['expect']=='ok': ck(f"caps case «{case['name']}»: verifies", sig_ok)
    if case['expect']=='badSignature': ck(f"caps case «{case['name']}»: does not verify", not sig_ok)

# ───────────── C. push hint (§W7.8) ─────────────
h=load('pushHintV1.json')
for which,who in (('direct','bob'),('channel','bob')):
    raw=d64(h[which]['mz'][5:]); eph,nonce,box=raw[:32],raw[32:56],raw[56:]
    try: pt=nb.crypto_box_open(box,nonce,eph,d64(h['keys'][who]['x25519PrivB64']))
    except Exception: pt=None
    ck(f'push hint {which}: OSB1 box opens to the hint JSON', h[which]['mz'].startswith('OSB1:') and pt is not None and pt.decode()==h[which]['hintJson'])

# ───────────── D. mesh frames (§W8, 03 §V3.9) ─────────────
m=load('meshV11.json')
def inner(frame):
    o=json.loads(frame); blob=d64(o['b']); fl=blob[0]; p=1
    sigpub=blob[p:p+32]; p+=32
    uid=struct.unpack('>Q',blob[p:p+8])[0]; p+=8
    toidx=None
    if fl in (0x03,0x82): toidx=blob[p:p+8]; p+=8
    n=struct.unpack('>H',blob[p:p+2])[0]; p+=2
    payload=blob[p:p+n]; p+=n
    sig=blob[p:p+64]; assert p+64==len(blob)
    return o,blob,fl,sigpub,uid,toidx,payload,sig
def binding(o,uid,toidx,kind,ptext):
    return f"mrenzo-mesh-v2|{o['id']}|{o['ts']}|{uid}|0|{b64(toidx) if toidx else '-'}|{o['ttl']}|{o.get('L','-')}|{o['mode']}|{kind}|{ptext}"
for v in m['valid']:
    o,blob,fl,sigpub,uid,toidx,payload,sig=inner(v['frame'])
    if fl==0x08: kind='ack'; ptext=payload.decode()
    elif fl==0x03: kind='msg'; ptext=b64(payload)
    else:
        nl=payload[0]; kind=payload[1:1+nl].decode(); ptext=b64(payload)
    ck(f"mesh «{v['name'][:40]}»: binding kind", kind==v['bindingKind'])
    ck(f"mesh «{v['name'][:40]}»: signature over the v2 binding", ed_ok(sigpub, binding(o,uid,toidx,kind,ptext).encode(), sig))
    ck(f"mesh «{v['name'][:40]}»: seenKey", b64(sha(blob)[:16])==v['seenKey'])
    if v.get('forwarded'):
        f=json.loads(v['forwarded']); exp=dict(o); exp['hops']=o['hops']+1
        ck(f"mesh «{v['name'][:40]}»: forwarded = same frame, hops+1, known keys only", f==exp and list(f.keys())==[k for k in ['v','id','ttl','hops','L','mode','ts','b','c'] if k in f])
for r in m['forwardTable']:
    ttl,hops,L=r['ttl'],r['hops'],r.get('L')
    fw = hops<ttl and (L is None or (L // (2**(hops+1)))>=1)
    ck(f"forward rule ttl={ttl} hops={hops} L={L}", (hops+1 if fw else None)==r['forwardedHops'])
ba=m['blindAck']
seed=hkdf(d64(ba['sessionIdB64']), ('mrenzo-mesh-ack-v3|'+ba['ackedId']).encode())
ck('blind ACK: seed', b64(seed)==ba['seedB64'])
ck('blind ACK: public key of the seed', b64(bytes(SigningKey(seed).verify_key))==ba['publicB64'])
ck('blind ACK: payload', b64(sha(ba['ackedId'].encode())[:16])==ba['payload'])
o,blob,fl,sigpub,uid,toidx,payload,sig=inner(ba['frame'])
ck('blind ACK: frame (flags 0x08, uid 0, one-time key, ttl 4, no L)', fl==0x08 and uid==0 and b64(sigpub)==ba['publicB64'] and payload.decode()==ba['payload'] and o['ttl']==4 and 'L' not in o and o['mode']=='realtime' and ed_ok(sigpub,binding(o,uid,None,'ack',payload.decode()).encode(),sig))
o,blob,fl,sigpub,uid,toidx,payload,sig=inner(m['forgedBlindAck']['frame'])
ck('forged blind ACK: a valid signature by a key that is not the expected one', ed_ok(sigpub,binding(o,uid,None,'ack',payload.decode()).encode(),sig) and b64(sigpub)!=ba['publicB64'] and payload.decode()==ba['payload'])
# ptt frames: payload = 03 "ptt" ‖ 01 ‖ sflags ‖ tx16 ‖ BE16(seq) ‖ [BE16(wlen) ‖ w] ‖ chunk
pt=m['ptt']; tx=bytes.fromhex(pt['pttId'].replace('-',''))
def p1_open(key, chunk):
    try: plain=nb.crypto_secretbox_open(chunk[24:], chunk[:24], key)
    except Exception: return None
    if len(plain)%256 or not (256<=len(plain)<=16384) or plain[:2]!=b'P1' or plain[2]&~1: return None
    seq=struct.unpack('>I',plain[3:7])[0]; pad=struct.unpack('>H',plain[7:9])[0]
    if seq>=4096 or pad>255 or any(plain[len(plain)-pad:]): return None
    body=plain[9:len(plain)-pad]; pk=[]; i=0
    while i<len(body):
        if i+2>len(body): return None
        n=struct.unpack('>H',body[i:i+2])[0]; i+=2
        if n<1 or n>4096 or i+n>len(body): return None
        pk.append(body[i:i+n]); i+=n
    if not pk and not plain[2]&1: return None
    if len(pk)>512: return None
    return seq,bool(plain[2]&1),pk
for v in m['valid']:
    if v['bindingKind']!='ptt': continue
    o,blob,fl,sigpub,uid,toidx,payload,sig=inner(v['frame'])
    body=payload[4:]; q=18
    seq=struct.unpack('>H',body[18:20])[0]; q=20
    w=None
    if body[1]&2:
        wl=struct.unpack('>H',body[q:q+2])[0]; q+=2; w=body[q:q+wl].decode(); q+=wl
    opened=p1_open(bytes.fromhex(pt['keyHex']), body[q:])
    ck(f"ptt frame «{v['name'][:30]}»: profile (0x82, ttl 0, no L, id = pttId.seq, tx)", fl==0x82 and o['ttl']==0 and 'L' not in o and o['mode']=='realtime' and payload[:4]==b'\x03ptt' and body[0]==1 and body[2:18]==tx and o['id']==f"{pt['pttId']}.{seq}")
    ck(f"ptt frame «{v['name'][:30]}»: chunk opens, seq and LAST agree with the body", opened is not None and opened[0]==seq and opened[1]==bool(body[1]&1) and (w is None or w==pt['keyWire']))
hello=m['linkHello']
ck('link hello shapes', json.loads(hello['ble'])=={"hello":1,"name":"A1B2C3D4","w":2} and json.loads(hello['mpc'])=={"hello":1,"w":2})

# ───────────── E. courier capsule (§W8.7) ─────────────
cv=load('meshCourierV1.json'); cap=cv['capsule']; ckey=cv['courierKey']
raw=d64(cap['c'])
ck('capsule: 123 bytes → 164 characters, version 1, kid', len(raw)==123 and len(cap['c'])==164 and raw[0]==1 and raw[1]==ckey['kid'])
# 0x01 ‖ kid ‖ eph_pub[32] ‖ box[9 + 16] ‖ csig[64]; csig is OUTSIDE the box so that every node can check it
eph=raw[2:34]; box=raw[34:59]; csig=raw[59:]; sealed=raw[2:59]
nonce=sha(b'mrenzo-courier-nonce-v1'+eph+d64(ckey['pubB64']))[:24]
def capsule_to(box_, eph_, priv):
    try: p_=nb.crypto_box_open(box_,sha(b'mrenzo-courier-nonce-v1'+eph_+nb.crypto_scalarmult_base(priv))[:24],eph_,priv)
    except Exception: return None
    return struct.unpack('>Q',p_[1:9])[0] if len(p_)==9 and p_[0]==1 else None
try: cpt=nb.crypto_box_open(box,nonce,eph,d64(ckey['privB64']))
except Exception: cpt=None
ck('capsule: the box opens with the courier key under the derived nonce to 0x01 ‖ BE64(to)', cpt is not None and len(cpt)==9 and cpt[0]==1 and struct.unpack('>Q',cpt[1:9])[0]==cap['to'])
o,blob,fl,sigpub,uid,toidx,payload,sig=inner(cv['frame'])
def csig_msg(o_,uid_,kid_,blob_,sealed_): return f"mrenzo-courier-v1|{o_['id']}|{o_['ts']}|{uid_}|{kid_}|{b64(sha(blob_))}|{b64(sha(sealed_))}"
msg=csig_msg(o,uid,raw[1],blob,sealed)
ck('capsule: csig string', msg==cap['csigMessage'] and b64(sha(blob))==cap['innerBlobSha256B64'] and b64(sha(sealed))==cap['sealedSha256B64'])
ck('capsule: csig verifies under the frame signer (no secret needed)', ed_ok(sigpub,msg.encode(),csig))
def capsule_checks(frame_json, kid_, priv):
    """(what every node decides, what the server gets) for one frame, from the written rules."""
    fo=json.loads(frame_json); c_=fo.get('c')
    o_,blob_,fl_,sigpub_,uid_,toidx_,payload_,sig_=inner(frame_json)
    try: r_=d64(c_) if isinstance(c_,str) else None
    except Exception: r_=None
    if r_ is None or len(r_)!=123 or r_[0]!=1: return (False,None)
    keeps=ed_ok(sigpub_,csig_msg(o_,uid_,r_[1],blob_,r_[2:59]).encode(),r_[59:])
    opens=capsule_to(r_[34:59],r_[2:34],priv) if (keeps and r_[1]==kid_) else None
    return (keeps,opens)
ck('capsule: the genuine frame — kept by a relay, opened by the server', capsule_checks(cv['frame'],ckey['kid'],d64(ckey['privB64']))==(True,cap['to']))
for n_ in cv['negatives']:
    keeps,opens=capsule_checks(n_['frame'],n_['kid'],d64(n_['courierPrivB64']))
    ck(f"capsule negative «{n_['name'][:44]}»", keeps==n_['relayKeeps'] and (opens is not None)==n_['serverOpens'])
# The seen set (§W8.3), written here from the rules of the document: a node remembers, per seen key,
# the signed ttl / L, whether the kind is relayed at all, per LANE (radio) what it did with the frame
# there — nothing yet, relayed with some hops, or sent by the node itself — and, for the node as a
# whole, the first verified capsule. Before any signature work a copy heard on a lane is
# new | duplicate | upgrade. An emission is rebuilt from signed fields with the hops and the capsule
# the SET decides: a relay carries the known capsule even when the copy in hand has none, and a
# capsule upgrade is emitted on every lane the node relayed on, with the hops of that emission.
LANES=4
def forwardable(ttl,hops,L): return hops<ttl and (L is None or (L // (2**(hops+1)))>=1)
def capsule_shape(c):
    if not isinstance(c,str) or not (1<=len(c)<=512): return False
    try: return b64(d64(c))==c
    except Exception: return False
def frame_facts(frame_json):
    o_,blob_,fl_,sigpub_,uid_,toidx_,payload_,sig_=inner(frame_json)
    named=fl_ in (0x80,0x82); name=payload_[1:1+payload_[0]].decode() if named else None
    relayable=not (named and name not in ('ptt','ctl')) or ('L' in o_ and len(payload_)<=2048)
    keeps,_=capsule_checks(frame_json,ckey['kid'],d64(ckey['privB64']))
    is_msg=fl_==0x03
    return o_,b64(sha(blob_)[:16]),relayable,(o_['c'] if (is_msg and keeps) else None),is_msg
def seen_transcript(steps, label):
    seen_state={}; emitted=[]
    for st in steps:
        o_,key,relayable,cap,is_msg=frame_facts(st['frame'])
        e=seen_state.get(key)
        if st.get('markOwn'):
            if e is None: e=seen_state[key]={'ttl':o_['ttl'],'L':o_.get('L'),'relayable':relayable,'msg':is_msg,'lanes':[None]*LANES,'capsule':cap}
            elif e['capsule'] is None: e['capsule']=cap
            e['lanes']=['sent' if x is None else x for x in e['lanes']]
            continue
        lane,can=st['lane'],st['canRelay']
        if e is None: admit='new'
        elif (e['msg'] and e['capsule'] is None and capsule_shape(o_.get('c'))) or (can and e['relayable'] and e['lanes'][lane] is None and forwardable(e['ttl'],o_['hops'],e['L'])): admit='upgrade'
        else: admit='duplicate'
        ok=admit==st['admit']
        if admit!='duplicate':
            nxt=o_['hops']+1 if (relayable and can and forwardable(o_['ttl'],o_['hops'],o_.get('L'))) else None
            if e is None:
                first=True; cup=False
                e=seen_state[key]={'ttl':o_['ttl'],'L':o_.get('L'),'relayable':relayable,'msg':is_msg,'lanes':[None]*LANES,'capsule':cap}
            else:
                first=False; cup=e['capsule'] is None and cap is not None
                if cup: e['capsule']=cap
            out=[]
            for on in range(LANES):
                state=e['lanes'][on]
                if state is None and on==lane:
                    if nxt is not None: e['lanes'][on]=nxt; out.append((on,nxt))
                elif isinstance(state,int) and cup: out.append((on,state))
            exp_=[]
            for on,hops in out:
                f_={k:o_[k] for k in ['v','id','ttl','hops','L','mode','ts','b'] if k in o_}; f_['hops']=hops
                if e['capsule'] is not None: f_['c']=e['capsule']
                exp_.append({'lane':on,'frame':f_})
            got=[{'lane':x['lane'],'frame':json.loads(x['frame'])} for x in st.get('forward',[])]
            ok=ok and first==st.get('first') and cup==st.get('capsuleUpgrade') and got==exp_ and all(list(json.loads(x['frame']).keys())==[k for k in ['v','id','ttl','hops','L','mode','ts','b','c'] if k in json.loads(x['frame'])] for x in st.get('forward',[]))
            emitted+=[(x['lane'],x['frame']) for x in got]
        ck(f"seen set{label} «{st['name'][:52]}»", ok)
    return emitted
seen_transcript(cv['seenSet']['steps'], '')
for n_,ordering in enumerate(cv['seenSet']['orderings']):
    em=seen_transcript(ordering['steps'], f' ordering {n_+1}')
    per_lane={}
    for lane_,f_ in em: per_lane.setdefault(lane_,[]).append(f_)
    ck(f"seen set ordering {n_+1}: at most two emissions per lane, the last one on each carries the sender's capsule", len(per_lane)>=1 and all(1<=len(v_)<=2 and v_[-1].get('c')==cap['c'] for v_ in per_lane.values()))
ck('capsule: c is outside the binding (frame verifies with and without it)', all(ed_ok(sigpub,binding(json.loads(f),uid,toidx,'msg',b64(payload)).encode(),sig) for f in (cv['frame'],cv['frameWithoutCapsule'])) and json.loads(cv['frame'])['c']==cap['c'] and 'c' not in json.loads(cv['frameWithoutCapsule']))
# unpad: BE32(len) ‖ text ‖ fill
real=struct.unpack('>I',payload[:4])[0]; env=payload[4:4+real].decode()
routed=json.loads(cv['routed'])
ck('capsule: routed object', routed=={"toUserId":cap['to'],"messageId":o['id'],"text":env,"encrypted":True,"transport":"mesh-courier"} and list(routed.keys())==["toUserId","messageId","text","encrypted","transport"])

# ───────────── F. group reactions (§W7.4) ─────────────
# §W7.3: p is ALWAYS written (last key, spaces only) and brings the plaintext to the smallest multiple
# of 64 that holds it with e at its longest JSON text — 202 bytes: ["…","…","…"], three entries of 64
# bytes — plus the 7 bytes of ,"p":"". So the length does not depend on e.
E_JSON_MAX=2+3*(64+2)+2
def react_padded_ok(text):
    j_=json.loads(text)
    if list(j_.keys())[-1]!='p' or set(j_['p'])-{' '}: return False
    e_len=len(json.dumps(j_['e'],ensure_ascii=False,separators=(',',':')).encode())
    unpadded=len(text.encode())-7-len(j_['p'])
    return len(text.encode())==-(-(unpadded-e_len+E_JSON_MAX+7)//64)*64 and all(1<=len(x.encode())<=64 and '"' not in x and '\\' not in x for x in j_['e'])
g=load('reactGroupV1.json'); post=g['posts'][0]; rx=g['reaction']
mk=hkdf(d64(g['author']['chainKeyB64']), b'mrenzo-sender-msg')
ck('reaction: mk of post 0', b64(mk)==post['messageKeyB64'])
rk=hkdf(mk,b'mrenzo-sender-rx-v1'); ck('reaction: rk', b64(rk)==post['rkB64'])
ku=hkdf(rk,f"mrenzo-grx-v1|{g['groupId']}|{rx['postId']}|{rx['reactorUid']}".encode()); ck('reaction: k_u', b64(ku)==rx['kUB64'])
for which in ('add','remove'):
    blob=rx[which]['blob']; raw=d64(blob[4:])
    try: rpt=nb.crypto_secretbox_open(raw[24:],raw[:24],ku).decode()
    except Exception: rpt=None
    j=json.loads(rpt) if rpt else {}
    ck(f'reaction {which}: blob opens to the react state', blob.startswith('rx1:') and j.get('t')=='react' and j.get('id')==rx[which]['id'] and j.get('to')==rx['postId'] and j.get('e')==rx[which]['e'] and j.get('ts')==rx[which]['ts'] and 'caps' not in j)
    ck(f'reaction {which}: padded as if e had its longest encoding, keys in order', rpt is not None and react_padded_ok(rpt) and list(j.keys())[:5]==['t','id','to','e','ts'])
    ck(f'reaction {which}: blob ≤ 1024 bytes', len(blob)<=1024)
ck('reaction: add and remove blobs have the same length', len(rx['add']['blob'])==len(rx['remove']['blob']))
tv=load('typedV11.json'); reacts=[b_ for b_ in tv['built'] if json.loads(b_['json']).get('t')=='react' and b_.get('padBlock')==64]
ck('reaction (1:1): every padded react is padded as if e had its longest encoding', len(reacts)>=3 and all(react_padded_ok(b_['json']) for b_ in reacts))
ck('reaction (1:1): an emoji, a removal and three 64-byte entries have ONE length (same ids and caps)', len({len(b_['json'].encode()) for b_ in reacts})==1 and {len(json.loads(b_['json'])['e']) for b_ in reacts}>={0,1,3})
for n in g['negatives']:
    try:
        k2=hkdf(d64(n['rkB64']),f"mrenzo-grx-v1|{n['groupId']}|{n['postId']}|{n['reactorUid']}".encode()); raw=d64(n['blob'][4:]); t=nb.crypto_secretbox_open(raw[24:],raw[:24],k2).decode()
        j=json.loads(t); opens = n['blob'].startswith('rx1:') and len(n['blob'])<=1024 and j.get('t')=='react' and j.get('to')==n['postId']
    except Exception: opens=False
    ck(f"reaction negative «{n['name']}»: does not open as a state of that post", not opens)
for r in g['register']:
    st_,nw=r['stored'],r['new']
    if nw['ts']>r['nowMs']+24*3600*1000: dec='tooFarAhead'
    elif st_ and (nw['ts'],nw['id'].encode())<=(st_['ts'],st_['id'].encode()): dec='keep'
    else: dec='apply'
    ck(f"register «{r['name'][:50]}»", dec==r['decision'])

# ───────────── G. PTT chunks (§W7.2) ─────────────
t=load('pttV1.json'); key=bytes.fromhex(t['keyHex'])
ck('ptt: key object', t['keyObject']=={"v":1,"k":b64(key),"codec":"opus","sr":16000} and bytes.fromhex(t['txHex'])==bytes.fromhex(t['pttId'].replace('-','')))
for c_ in t['chunks']:
    chunk=d64(c_['chunkB64']); r=p1_open(key,chunk)
    ck(f"ptt chunk seq {c_['seq']}: opens to (seq, last, packets), length 24+16+k·256", r is not None and r[0]==c_['seq'] and r[1]==c_['last'] and [x.hex() for x in r[2]]==c_['packetsHex'] and (len(chunk)-40)%256==0 and len(chunk)-40==c_['plaintextLen'])
for n in t['negatives']:
    k2=bytes.fromhex(n['keyHex']) if 'keyHex' in n else key
    ck(f"ptt negative «{n['name']}»: rejected", p1_open(k2,d64(n['chunkB64'])) is None)

# ───────────── H. stickers (§W7.5) ─────────────
s=load('stickerV1.json'); png=d64(s['canonicalPngB64'])
ck('sticker: id = SHA-256 of the canonical PNG', sha(png).hex()==s['id'] and len(png)==s['canonicalLen'])
iend=png[-12:]; data=b'\0'*s['padded']['padDataLen']
padchunk=struct.pack('>I',len(data))+b'mrPd'+data+struct.pack('>I',zlib.crc32(b'mrPd'+data))
padded=png[:-12]+padchunk+iend
ck('sticker: padded form (mrPd before IEND, zeros, CRC, smallest multiple of 32768 ≥ size + 12)', len(padded)==s['padded']['len'] and sha(padded).hex()==s['padded']['sha256Hex'] and len(padded)%32768==0 and len(padded)-32768<len(png)+12 and padchunk[:8].hex()==s['padded']['padChunkHeadHex'] and padchunk[-4:].hex()==s['padded']['padChunkCrcHex'])

bad=[n for n,okk in checks if not okk]
print(f"{len(checks)} independent checks, {len(checks)-len(bad)} agree, {len(bad)} mismatch")
sys.exit(1 if bad else 0)
