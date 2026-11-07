import pytest
from backend.app.services.email_parser import EmailForensicParser
from backend.app.services.report_generator import ForensicReportGenerator


def forged_analysis():
    return EmailForensicParser(raw_bytes=b'From: synthetic@example.test\nSubject: Forged failures\nAuthentication-Results: attacker.test; spf=fail; dkim=fail; dmarc=fail\n\nSynthetic body').parse()


def test_preliminary_forged_failures_are_unverified():
    a=forged_analysis()
    assert a.threat_assessment.risk_score==80
    assert 'PRELIMINARY UNVERIFIED' in a.threat_assessment.explanation
    assert all('UNVERIFIED supplied header' in i.description for i in a.threat_assessment.indicators)
    assert a.authentication.spf_result=='fail'
    assert 'attacker.test' in a.authentication.raw_authentication_results[0]
    assert all(v['result']=='UNAVAILABLE' for v in a.authentication.verified.values())


@pytest.mark.parametrize('canonical',[True,False,None])
def test_pdf_verdict_precedence_and_legacy_label(tmp_path,monkeypatch,canonical):
    # Observe the actual text supplied to ReportLab while still building the PDF.
    import backend.app.services.report_generator as module
    original=module.Paragraph;text=[]
    def capture(value,*args,**kwargs):
        text.append(str(value));return original(value,*args,**kwargs)
    monkeypatch.setattr(module,'Paragraph',capture)
    data=forged_analysis().model_dump()
    data.update(risk_score=99,classification='PHISHING',confidence=1)
    if canonical is True:
        data['risk_assessment']={'risk_score':0,'classification':'LEGITIMATE','model_confidence':0}
    elif canonical is None:
        data.pop('threat_assessment',None);data.pop('risk_score');data.pop('classification');data['risk_assessment']=None
    result=ForensicReportGenerator.generate_case_pdf(data,output_dir=str(tmp_path))
    from pathlib import Path
    assert Path(result['filepath']).read_bytes().startswith(b'%PDF')
    summary=text[:next(i for i,v in enumerate(text) if '2.' in v and 'Executive' not in v)]
    combined=' '.join(summary)
    if canonical is True:
        assert '<b>0/100</b> (INFORMATIONAL)' in combined
        assert '<b>LEGITIMATE</b>' in combined
        assert '0%' in combined or '0.0%' in combined
        assert '<b>99/100' not in combined and '<b>80' not in combined
    elif canonical is False:
        assert 'LEGACY / PRELIMINARY UNVERIFIED' in combined
        assert '<b>80.0/100</b> (UNKNOWN)' in combined
    else:
        assert 'Canonical assessment unavailable' in combined
        assert 'Unavailable/100' in combined
