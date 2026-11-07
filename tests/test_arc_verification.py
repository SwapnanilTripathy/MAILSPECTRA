import base64
import dkim
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from backend.app.services.auth_verification import verify_arc


def test_signed_arc_chain_and_tampered_body():
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    private=key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.TraditionalOpenSSL,serialization.NoEncryption())
    public=key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
    raw=b'From: author@example.test\r\nTo: recipient@example.test\r\nSubject: Synthetic ARC\r\nAuthentication-Results: mx.example.test; dkim=pass header.d=example.test\r\n\r\nOriginal body\r\n'
    headers=dkim.arc_sign(raw,b'test',b'example.test',private,b'mx.example.test')
    assert headers
    def dnsfunc(*args,**kwargs):return b'v=DKIM1; k=rsa; p='+base64.b64encode(public)
    signed=b''.join(headers)+raw
    assert verify_arc(signed,dnsfunc)['result']=='pass'
    assert verify_arc(signed.replace(b'Original body',b'Tampered body'),dnsfunc)['result']=='fail'
    assert verify_arc(raw,dnsfunc)['result']=='none'


def test_arc_work_budget():
    assert verify_arc(b'ARC-Seal: i=1;\r\n'*11+b'From: example@example.test\r\n\r\nbody')['result']=='UNAVAILABLE'
