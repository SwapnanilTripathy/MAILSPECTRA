import pytest
from httpx import ASGITransport, AsyncClient
from backend.app.main import app


@pytest.mark.asyncio
async def test_masked_analysis_preserves_full_unmasked_case(phishing_eml_bytes):
    async with AsyncClient(transport=ASGITransport(app=app), base_url='http://test') as client:
        response = await client.post('/api/v1/analyze/email?mask_pii=true', files={'file': ('review-phishing.eml', phishing_eml_bytes, 'message/rfc822')})
        assert response.status_code == 200
        masked = response.json()
        assert masked['privacy_redaction_applied'] is True
        assert '*' in masked['metadata']['from_sender']['address']
        case = await client.get(f"/api/v1/cases/{masked['case_id']}")
        assert case.status_code == 200
        full = case.json()['full_analysis']
        assert full['privacy_redaction_applied'] is False
        assert full['metadata']['from_sender']['address'] != masked['metadata']['from_sender']['address']
        assert full['evidence_hashes']['sha256'] == masked['evidence_hashes']['sha256']
        assert full['urls']
        assert 'authentication' in full and 'risk_assessment' in full
        assert 'campaign_correlations' in full


@pytest.mark.asyncio
async def test_case_total_and_paging_follow_all_filters():
    async with AsyncClient(transport=ASGITransport(app=app), base_url='http://test') as client:
        for i, kind in enumerate(('PHISHING', 'PHISHING', 'BENIGN')):
            response = await client.post('/api/v1/cases', json={'case_id': f'PAGING-REVIEW-{i}', 'filename': 'review.eml', 'subject': 'unique paging review', 'sha256': f'reviewhash{i}', 'classification': kind})
            assert response.status_code == 200
        response = await client.get('/api/v1/cases', params={'search': 'unique paging review', 'classification': 'PHISHING', 'limit': 1, 'offset': 1})
        assert response.json()['total'] == 2
        assert len(response.json()['items']) == 1
        response = await client.get('/api/v1/cases', params={'search': 'reviewhash2'})
        assert response.json()['total'] == 1
        assert response.json()['items'][0]['case_id'] == 'PAGING-REVIEW-2'
