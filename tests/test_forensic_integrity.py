import pytest
import dkim
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from backend.app.services.auth_verification import verify_dkim, dmarc_alignment, verify_authentication
from backend.app.services.email_parser import EmailForensicParser
from backend.app.utils.network import classify_ip, extract_ips_from_text

@pytest.mark.parametrize('address', ['192.0.2.1','198.51.100.25','203.0.113.88','100.64.0.1','0.0.0.0','240.0.0.1','224.0.0.1','2001:db8::1','::1','fe80::1'])
def test_special_use_is_not_public(address):
    assert not classify_ip(address)['is_public']

def test_ipv6_and_reported_header_provenance():
    assert '::1' in extract_ips_from_text('[::1]')
    analysis = EmailForensicParser(b'From: sender@example.test\nTo: one@example.test\nTo: two@example.test\nAuthentication-Results: forged; spf=pass; dkim=pass; dmarc=pass\n\nhello').parse()
    assert len(analysis.metadata.to_recipients) == 2
    assert len([h for h in analysis.metadata.raw_headers if h['name']=='To']) == 2
    assert analysis.authentication.reported_status == 'UNTRUSTED_HEADER_CLAIMS'
    assert analysis.authentication.verified['dkim']['result'] == 'UNAVAILABLE'

def test_dkim_valid_and_tampered_signature():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    import base64
    raw = b'From: sender@example.test\r\nTo: user@example.test\r\nSubject: DKIM synthetic test\r\n\r\nOriginal body\r\n'
    signature = dkim.sign(raw, b'test', b'example.test', private, include_headers=[b'from', b'to', b'subject'])
    def dnsfunc(name, **kwargs): return b'v=DKIM1; k=rsa; p=' + base64.b64encode(public)
    assert verify_dkim(signature+raw, dnsfunc)['result'] == 'pass'
    assert verify_dkim(signature+raw.replace(b'Original body',b'Changed body'), dnsfunc)['result'] == 'fail'
    assert verify_dkim(raw, dnsfunc)['result'] == 'none'

def test_dmarc_uses_verified_alignment_and_retains_unknown():
    assert dmarc_alignment('example.test', {'result':'UNAVAILABLE'}, {'result':'pass','domains':['example.test']}, 'v=DMARC1; p=reject')['result'] == 'pass'
    assert dmarc_alignment('example.test', {'result':'UNAVAILABLE'}, {'result':'fail'}, 'v=DMARC1; p=reject')['result'] == 'UNAVAILABLE'
    assert dmarc_alignment('example.test', {'result':'fail'}, {'result':'pass','domains':['other.test']}, 'v=DMARC1; p=reject')['result'] == 'fail'

@pytest.mark.asyncio
async def test_saved_artifact_cannot_invent_spf_context():
    result = await verify_authentication(b'From: forged@example.test\n\nhello','example.test')
    assert result['spf']['result'] == 'UNAVAILABLE'
    assert result['dkim']['result'] == 'UNAVAILABLE'
