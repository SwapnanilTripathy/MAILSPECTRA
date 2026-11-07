from backend.app.services.email_parser import EmailForensicParser
from backend.app.graph.graph_builder import ThreatGraphBuilder
from backend.app.graph.campaign_correlator import CampaignCorrelator
import networkx as nx

def test_observed_hops_and_graph_metric_definition():
    raw=b'Received: from b.example.test by c.example.test; Tue, 01 Sep 2026 12:00:02 +0000\nReceived: from a.example.test by b.example.test; Tue, 01 Sep 2026 12:00:01 +0000\nFrom: user@example.test\nSubject: relay test\n\nbody'
    graph=ThreatGraphBuilder.serialize_graph(ThreatGraphBuilder.build_case_graph(EmailForensicParser(raw).parse()))
    hops=[edge for edge in graph.edges if edge.relationship=='RECEIVED_FROM']
    assert {(edge.source,edge.target) for edge in hops} == {('mail_server:a.example.test','mail_server:b.example.test'),('mail_server:b.example.test','mail_server:c.example.test')}
    assert all(edge.evidence_refs and edge.provenance=='OBSERVED_UNTRUSTED_HEADER' for edge in hops)
    assert all(edge.evidence_refs for edge in graph.edges)
    duplicate=nx.MultiDiGraph();duplicate.add_edge('a','b');duplicate.add_edge('a','b');duplicate.add_edge('a','a')
    assert ThreatGraphBuilder.serialize_graph(duplicate).density == 0.5

def test_header_pass_does_not_prove_authenticity(benign_eml_bytes):
    _,_,attribution=CampaignCorrelator.correlate_case(EmailForensicParser(benign_eml_bytes).parse(),[])
    assert attribution.assessment=='INSUFFICIENT_EVIDENCE'
    assert attribution.confidence==0
