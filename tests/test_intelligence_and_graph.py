import os
import pytest
from httpx import ASGITransport, AsyncClient

from backend.app.graph.campaign_correlator import CampaignCorrelator
from backend.app.graph.graph_builder import ThreatGraphBuilder
from backend.app.graph.schemas import GraphEdgeType, GraphNodeType
from backend.app.intelligence.dns_intelligence import DNSIntelligenceService
from backend.app.intelligence.domain_intelligence import DomainIntelligenceService
from backend.app.intelligence.geoip import OfflineGeoIPProvider
from backend.app.intelligence.ip_intelligence import IPIntelligenceService
from backend.app.intelligence.rdap import RDAPClientService
from backend.app.intelligence.reputation import ThreatReputationService
from backend.app.main import app
from backend.app.schemas.analysis import EmailAnalysisResponse
from backend.app.services.email_parser import EmailForensicParser
from backend.app.services.threat_pipeline import ThreatAnalysisPipeline


@pytest.fixture
def pipeline_instance():
    return ThreatAnalysisPipeline()


# 1. Public IP Intelligence Test
@pytest.mark.asyncio
async def test_1_public_ip_intelligence():
    provider = OfflineGeoIPProvider()
    res = await provider.lookup("198.51.100.25")
    assert res.is_public is False  # Documentation prefix, even in a fixture
    assert res.is_private is False
    assert res.country == "United States"
    assert res.asn == "AS15169"
    assert res.status == "FIXTURE"
    assert res.confidence > 0.5


# 2. Private IP Handling Test
@pytest.mark.asyncio
async def test_2_private_ip_handling():
    provider = OfflineGeoIPProvider()
    for priv_ip in ["10.0.1.50", "192.168.1.1", "172.16.0.1", "127.0.0.1"]:
        res = await provider.lookup(priv_ip)
        assert res.is_private is True
        assert res.is_public is False
        assert res.status == "PRIVATE_IP"
        assert "Private" in (res.organization or "")


# 3. Missing / Invalid IP Handling Test
@pytest.mark.asyncio
async def test_3_missing_invalid_ip_handling():
    provider = OfflineGeoIPProvider()
    res = await provider.lookup("999.999.999.999")
    assert res.status == "INVALID_IP"
    assert res.is_public is False


# 4. DNS Success Test
@pytest.mark.asyncio
async def test_4_dns_success():
    dns_svc = DNSIntelligenceService(mode="offline")
    res = await dns_svc.resolve_domain("legitcorp.com")
    assert res.status == "FIXTURE"
    assert "198.51.100.25" in res.a_records
    assert any("mail-out.legitcorp.com" in mx for mx in res.mx_hosts)
    assert res.has_valid_mx is True


# 5. DNS Failure / Unknown Domain Test
@pytest.mark.asyncio
async def test_5_dns_unknown_domain():
    dns_svc = DNSIntelligenceService(mode="offline")
    res = await dns_svc.resolve_domain("non-existent-random-domain-12345.xyz")
    assert res.status == "UNAVAILABLE"  # Offline absence is not a successful lookup
    assert res.has_valid_mx is False


# 6. Domain Analysis (Entropy, Punycode, Lookalike, Suspicious TLD) Test
def test_6_domain_lexical_analysis():
    dom_svc = DomainIntelligenceService()

    # Suspicious TLD & Brand Lookalike
    susp_dom = dom_svc.analyze_lexical_domain("secure-micr0s0ft-login.xyz")
    assert susp_dom.suspicious_tld_flag is True
    assert susp_dom.is_lookalike is True
    assert any("HIGH_RISK_TLD" in sig for sig in susp_dom.risk_signals)

    # Punycode
    puny_dom = dom_svc.analyze_lexical_domain("xn--pple-43d.com")
    assert puny_dom.is_punycode is True
    assert any("IDN_PUNYCODE" in sig for sig in puny_dom.risk_signals)

    # Clean Domain
    clean_dom = dom_svc.analyze_lexical_domain("google.com")
    assert clean_dom.suspicious_tld_flag is False
    assert clean_dom.is_punycode is False


# 7. RDAP Unavailable / Graceful Handling Test
@pytest.mark.asyncio
async def test_7_rdap_graceful_handling():
    rdap_svc = RDAPClientService(mode="offline")
    res = await rdap_svc.lookup_domain("unregistered-unknown-domain-999.org")
    assert res.lookup_status in ["UNAVAILABLE", "NOT_FOUND"]
    assert res.domain == "unregistered-unknown-domain-999.org"


# 8. External Provider Unavailable Test
@pytest.mark.asyncio
async def test_8_external_provider_fallback():
    rep_svc = ThreatReputationService(mode="offline")
    res = await rep_svc.query_indicator("192.0.2.1", "IP")
    assert res.status in ["AVAILABLE", "UNAVAILABLE"]
    assert res.reputation_score >= 0.0


# 9. Relay Reconstruction Test
def test_9_relay_reconstruction(benign_eml_bytes):
    parser = EmailForensicParser(raw_bytes=benign_eml_bytes, filename="benign.eml")
    analysis = parser.parse()
    assert len(analysis.relay_chain.hops) >= 2
    assert analysis.relay_chain.hops[0].hop_index == 1
    assert analysis.relay_chain.hops[0].from_ip is not None


# 10. Origin Assessment Test
def test_10_origin_assessment(benign_eml_bytes, phishing_eml_bytes):
    parser_benign = EmailForensicParser(raw_bytes=benign_eml_bytes)
    res_benign = parser_benign.parse()
    origin_benign = IPIntelligenceService.assess_origin(res_benign)
    assert origin_benign.earliest_reliable_ip is not None
    assert origin_benign.confidence == 0.0  # Uploaded headers provide no calibrated trust
    assert len(origin_benign.evidentiary_basis) > 0
    assert len(origin_benign.limitations) > 0


# 11. Graph Construction Test
def test_11_graph_construction(phishing_eml_bytes):
    parser = EmailForensicParser(raw_bytes=phishing_eml_bytes, filename="phishing.eml")
    analysis = parser.parse()
    G = ThreatGraphBuilder.build_case_graph(analysis)
    assert G.number_of_nodes() >= 4
    assert G.number_of_edges() >= 3

    graph_data = ThreatGraphBuilder.serialize_graph(G)
    assert graph_data.total_nodes == G.number_of_nodes()
    assert graph_data.total_edges == G.number_of_edges()
    assert any(n.node_type == GraphNodeType.EMAIL.value for n in graph_data.nodes)


# 12. Graph Relationships Test
def test_12_graph_relationships(phishing_eml_bytes):
    parser = EmailForensicParser(raw_bytes=phishing_eml_bytes)
    analysis = parser.parse()
    G = ThreatGraphBuilder.build_case_graph(analysis)
    graph_data = ThreatGraphBuilder.serialize_graph(G)

    rel_types = {e.relationship for e in graph_data.edges}
    assert GraphEdgeType.SENT_FROM.value in rel_types
    assert GraphEdgeType.CONTAINS_URL.value in rel_types


# 13. Shared Infrastructure Detection Test
def test_13_shared_infrastructure_detection(phishing_eml_bytes):
    parser = EmailForensicParser(raw_bytes=phishing_eml_bytes, filename="case1.eml")
    analysis1 = parser.parse()

    # Create historical case representation sharing IP
    hist_cases = [
        {
            "case_id": "CASE-PAST-001",
            "filename": "previous_attack.eml",
            "subject": "Urgent Action Required",
            "from_address": "attacker@evil.com",
            "classification": "PHISHING",
            "ips": ["198.51.100.45"],
            "domains": ["global-banking-corp.com"],
            "urls": ["http://198.51.100.45/portal/login.php?session=928472910"],
        }
    ]

    matches, campaign, attribution = CampaignCorrelator.correlate_case(analysis1, hist_cases)
    assert len(matches) == 1
    assert matches[0].related_case_id == "CASE-PAST-001"
    assert matches[0].correlation_score >= 0.60
    assert "SHARED_IP_INFRASTRUCTURE" in matches[0].shared_indicators


# 14. Campaign Correlation Test
def test_14_campaign_correlation(phishing_eml_bytes):
    parser = EmailForensicParser(raw_bytes=phishing_eml_bytes)
    analysis = parser.parse()

    hist_cases = [
        {
            "case_id": "CASE-PAST-002",
            "filename": "past2.eml",
            "subject": "Account Alert",
            "from_address": "security-alert@global-banking-corp.com",
            "classification": "PHISHING",
            "ips": ["198.51.100.45"],
            "domains": ["global-banking-corp.com"],
            "urls": ["http://198.51.100.45/portal/login.php?session=928472910"],
        }
    ]

    matches, campaign, attribution = CampaignCorrelator.correlate_case(analysis, hist_cases)
    assert campaign is not None
    assert campaign.campaign_id.startswith("CAMPAIGN-")
    assert len(campaign.member_case_ids) == 2
    assert campaign.confidence >= 0.60


# 15. Attribution Support Output Test
def test_15_attribution_support_output(phishing_eml_bytes, benign_eml_bytes):
    # Test Phishing (Spoofed Identity)
    parser_phish = EmailForensicParser(raw_bytes=phishing_eml_bytes)
    analysis_phish = parser_phish.parse()
    _, _, attr_phish = CampaignCorrelator.correlate_case(analysis_phish, [])
    assert attr_phish.assessment in ["SPOOFED_IDENTITY", "DIRECT_MALICIOUS_INFRASTRUCTURE"]
    assert attr_phish.confidence > 0.5
    assert len(attr_phish.limitations) > 0

    # Test Benign (Legitimate Authenticated Sender)
    parser_benign = EmailForensicParser(raw_bytes=benign_eml_bytes)
    analysis_benign = parser_benign.parse()
    _, _, attr_benign = CampaignCorrelator.correlate_case(analysis_benign, [])
    assert attr_benign.assessment == "LEGITIMATE_AUTHENTICATED_SENDER"


# 16. Missing Intelligence Graceful Degradation Test
@pytest.mark.asyncio
async def test_16_missing_intelligence_degradation(pipeline_instance):
    raw_minimal = b"From: a@b.com\nTo: c@d.com\nSubject: Hi\n\nTest\n"
    res = await pipeline_instance.analyze_bytes_async(raw_minimal, filename="minimal.eml")
    assert res.success is True
    assert res.threat_graph is not None
    assert res.origin_assessment is not None
    assert res.attribution_support is not None


# 17. Multiple Emails Sharing Infrastructure Test
@pytest.mark.asyncio
async def test_17_multiple_emails_sharing_infrastructure(pipeline_instance, phishing_eml_bytes):
    # Analyze first email
    res1 = await pipeline_instance.analyze_bytes_async(phishing_eml_bytes, filename="phish1.eml")
    assert res1.success is True

    # Analyze second email sharing same payload
    res2 = await pipeline_instance.analyze_bytes_async(phishing_eml_bytes, filename="phish2.eml")
    assert res2.success is True
    assert res2.threat_graph.total_nodes > 0


# 18. API Integration Test with Full Phase 3 Response
@pytest.mark.asyncio
async def test_18_api_integration_phase3_response(phishing_eml_bytes, auth_headers):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=auth_headers) as client:
        files = {
            "file": ("phishing_test.eml", phishing_eml_bytes, "message/rfc822")
        }
        response = await client.post("/api/v1/analyze/email", files=files)
        assert response.status_code == 200
        data = response.json()

        # Verify Phase 1
        assert data["success"] is True
        assert data["case_id"].startswith("CASE-")
        assert len(data["relay_chain"]["hops"]) > 0

        # Verify Phase 2
        assert data["ai_inference"] is not None
        assert data["risk_assessment"] is not None
        assert data["shap_explanation"] is not None

        # Verify Phase 3
        assert "infrastructure_intelligence" in data
        assert "origin_assessment" in data
        assert "threat_graph" in data
        assert data["threat_graph"]["total_nodes"] > 0
        assert "attribution_support" in data
        assert data["attribution_support"]["assessment"] is not None
