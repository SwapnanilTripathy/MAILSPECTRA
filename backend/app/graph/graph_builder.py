from __future__ import annotations
from typing import TYPE_CHECKING, Any, Dict, List, Optional
import networkx as nx

from backend.app.graph.schemas import (
    GraphEdgeType,
    GraphNodeType,
    ThreatGraphData,
    ThreatGraphEdge,
    ThreatGraphNode,
)
from backend.app.utils.crypto import defang_ip, defang_url

if TYPE_CHECKING:
    from backend.app.intelligence.schemas import InfrastructureIntelligence
    from backend.app.schemas.analysis import EmailAnalysisResponse



class ThreatGraphBuilder:
    """Builds an authentic NetworkX threat graph connecting email artifacts, senders, domains,

    IPs, mail servers, ASNs, and geographic infrastructure.
    """

    @classmethod
    def build_case_graph(
        cls,
        analysis: EmailAnalysisResponse,
        intel: Optional[InfrastructureIntelligence] = None,
    ) -> nx.MultiDiGraph:
        """Construct NetworkX graph from analysis observables and infrastructure intelligence."""
        G = nx.MultiDiGraph()
        case_id = analysis.case_id
        email_node_id = f"email:{case_id}"

        # 1. Add Email / Case Root Node
        G.add_node(
            email_node_id,
            node_type=GraphNodeType.EMAIL.value,
            label=analysis.metadata.subject or f"Email ({case_id})",
            source="EMAIL_HEADER",
            confidence=1.0,
            properties={
                "case_id": case_id,
                "filename": analysis.filename,
                "classification": analysis.threat_assessment.classification,
                "risk_score": analysis.threat_assessment.risk_score,
                "sha256": analysis.evidence_hashes.sha256,
            },
        )

        # 2. Add Sender Node & Domain
        sender_addr = analysis.metadata.from_sender.address.lower()
        sender_domain = analysis.metadata.from_sender.domain.lower()

        if sender_addr:
            sender_node_id = f"sender:{sender_addr}"
            G.add_node(
                sender_node_id,
                node_type=GraphNodeType.SENDER.value,
                label=analysis.metadata.from_sender.display_name or sender_addr,
                source="EMAIL_HEADER",
                confidence=1.0,
                properties={"address": sender_addr, "display_name": analysis.metadata.from_sender.display_name},
            )
            G.add_edge(
                email_node_id,
                sender_node_id,
                relationship=GraphEdgeType.SENT_FROM.value,
                confidence=1.0,
                evidence=f"From: header specifies sender '{sender_addr}'",
            )

            if sender_domain:
                domain_node_id = f"domain:{sender_domain}"
                G.add_node(
                    domain_node_id,
                    node_type=GraphNodeType.DOMAIN.value,
                    label=sender_domain,
                    source="EMAIL_HEADER",
                    confidence=1.0,
                    properties={"domain": sender_domain},
                )
                G.add_edge(
                    sender_node_id,
                    domain_node_id,
                    relationship=GraphEdgeType.ASSOCIATED_WITH.value,
                    confidence=1.0,
                    evidence=f"Sender address domain '{sender_domain}'",
                )

        # 3. Add URLs and their target domains
        for url_item in analysis.urls:
            url_node_id = f"url:{url_item.url}"
            G.add_node(
                url_node_id,
                node_type=GraphNodeType.URL.value,
                label=url_item.defanged_url,
                source=url_item.source,
                confidence=1.0,
                properties={
                    "defanged_url": url_item.defanged_url,
                    "is_ip_host": url_item.is_ip_host,
                    "is_shortener": url_item.is_shortener,
                },
            )
            G.add_edge(
                email_node_id,
                url_node_id,
                relationship=GraphEdgeType.CONTAINS_URL.value,
                confidence=1.0,
                evidence=f"Hyperlink extracted from {url_item.source}",
            )

            # Link URL to host/domain or raw IP
            if url_item.is_ip_host and url_item.host:
                ip_node_id = f"ip:{url_item.host}"
                cls._ensure_ip_node(G, ip_node_id, url_item.host, intel)
                G.add_edge(
                    url_node_id,
                    ip_node_id,
                    relationship=GraphEdgeType.RESOLVES_TO.value,
                    confidence=1.0,
                    evidence="URL points directly to raw IP host",
                )
            elif url_item.registered_domain:
                url_dom_id = f"domain:{url_item.registered_domain}"
                G.add_node(
                    url_dom_id,
                    node_type=GraphNodeType.DOMAIN.value,
                    label=url_item.registered_domain,
                    source="URL_EXTRACTION",
                    confidence=1.0,
                    properties={"domain": url_item.registered_domain},
                )
                G.add_edge(
                    url_node_id,
                    url_dom_id,
                    relationship=GraphEdgeType.RESOLVES_TO.value,
                    confidence=1.0,
                    evidence=f"URL hosted under domain '{url_item.registered_domain}'",
                )

        # 4. Add Relay Hops & IP Infrastructure
        for hop in analysis.relay_chain.hops:
            if hop.from_ip:
                ip_node_id = f"ip:{hop.from_ip}"
                cls._ensure_ip_node(G, ip_node_id, hop.from_ip, intel)
                G.add_edge(
                    email_node_id,
                    ip_node_id,
                    relationship=GraphEdgeType.TRANSMITTED_VIA.value,
                    confidence=0.9 if hop.is_public_ip else 0.7,
                    evidence=f"Relay hop {hop.hop_index} from MTA IP {hop.from_ip}",
                )

            if hop.from_host:
                mta_node_id = f"mail_server:{hop.from_host}"
                G.add_node(
                    mta_node_id,
                    node_type=GraphNodeType.MAIL_SERVER.value,
                    label=hop.from_host,
                    source="RELAY_HEADER",
                    confidence=0.9,
                    properties={"hostname": hop.from_host, "hop_index": hop.hop_index},
                )
                G.add_edge(
                    email_node_id,
                    mta_node_id,
                    relationship=GraphEdgeType.TRANSMITTED_VIA.value,
                    confidence=0.9,
                    evidence=f"Relay hop {hop.hop_index} handled by MTA '{hop.from_host}'",
                )

        # 5. Enrich DNS and MX relationships from Intelligence
        if intel and intel.domain_intelligence:
            for dom_name, dom_intel in intel.domain_intelligence.items():
                dom_node_id = f"domain:{dom_name}"
                if dom_intel.dns:
                    # Add A record links (Domain -> IP)
                    for ip in dom_intel.dns.a_records:
                        ip_node_id = f"ip:{ip}"
                        cls._ensure_ip_node(G, ip_node_id, ip, intel)
                        G.add_edge(
                            dom_node_id,
                            ip_node_id,
                            relationship=GraphEdgeType.RESOLVES_TO.value,
                            confidence=0.95,
                            evidence=f"DNS A record maps '{dom_name}' to IP '{ip}'",
                        )
                    # Add MX links (Domain -> Mail Server)
                    for mx in dom_intel.dns.mx_hosts:
                        mx_node_id = f"mail_server:{mx}"
                        G.add_node(
                            mx_node_id,
                            node_type=GraphNodeType.MAIL_SERVER.value,
                            label=mx,
                            source="DNS",
                            confidence=0.95,
                            properties={"hostname": mx},
                        )
                        G.add_edge(
                            dom_node_id,
                            mx_node_id,
                            relationship=GraphEdgeType.ASSOCIATED_WITH.value,
                            confidence=0.95,
                            evidence=f"DNS MX record delegates mail for '{dom_name}' to '{mx}'",
                        )

        return G

    @classmethod
    def _ensure_ip_node(
        cls,
        G: nx.MultiDiGraph,
        ip_node_id: str,
        ip_val: str,
        intel: Optional[InfrastructureIntelligence],
    ) -> None:
        """Create IP node and linked ASN & Location nodes if intelligence exists."""
        geo_info = intel.ip_intelligence.get(ip_val) if (intel and intel.ip_intelligence) else None

        props: Dict[str, Any] = {"ip": ip_val, "defanged_ip": defang_ip(ip_val)}
        if geo_info:
            props.update({
                "country": geo_info.country,
                "city": geo_info.city,
                "asn": geo_info.asn,
                "isp": geo_info.isp,
                "is_public": geo_info.is_public,
            })

        G.add_node(
            ip_node_id,
            node_type=GraphNodeType.IP.value,
            label=defang_ip(ip_val),
            source="EMAIL_OBSERVABLE",
            confidence=1.0,
            properties=props,
        )

        if geo_info and geo_info.asn:
            asn_node_id = f"asn:{geo_info.asn}"
            G.add_node(
                asn_node_id,
                node_type=GraphNodeType.ASN.value,
                label=f"{geo_info.asn} ({geo_info.isp or 'Autonomous System'})",
                source="GEOIP",
                confidence=0.9,
                properties={"asn": geo_info.asn, "isp": geo_info.isp},
            )
            G.add_edge(
                ip_node_id,
                asn_node_id,
                relationship=GraphEdgeType.HOSTED_ON_ASN.value,
                confidence=0.9,
                evidence=f"IP is announced by autonomous system {geo_info.asn}",
            )

        if geo_info and geo_info.country:
            loc_node_id = f"location:{geo_info.country_code or geo_info.country}"
            G.add_node(
                loc_node_id,
                node_type=GraphNodeType.LOCATION.value,
                label=f"{geo_info.city or geo_info.region or ''}, {geo_info.country}".strip(", "),
                source="GEOIP",
                confidence=0.85,
                properties={"country": geo_info.country, "country_code": geo_info.country_code},
            )
            G.add_edge(
                ip_node_id,
                loc_node_id,
                relationship=GraphEdgeType.LOCATED_IN.value,
                confidence=0.85,
                evidence=f"IP route geolocates to {geo_info.country}",
            )

    @classmethod
    def serialize_graph(cls, G: nx.MultiDiGraph) -> ThreatGraphData:
        """Convert NetworkX MultiDiGraph into serializable ThreatGraphData model."""
        nodes_list: List[ThreatGraphNode] = []
        edges_list: List[ThreatGraphEdge] = []

        for node_id, data in G.nodes(data=True):
            nodes_list.append(
                ThreatGraphNode(
                    id=node_id,
                    node_type=data.get("node_type", GraphNodeType.EMAIL.value),
                    label=data.get("label", node_id),
                    source=data.get("source", "ANALYSIS"),
                    confidence=data.get("confidence", 1.0),
                    properties=data.get("properties", {}),
                )
            )

        for u, v, k, data in G.edges(data=True, keys=True):
            edges_list.append(
                ThreatGraphEdge(
                    source=u,
                    target=v,
                    relationship=data.get("relationship", GraphEdgeType.ASSOCIATED_WITH.value),
                    confidence=data.get("confidence", 1.0),
                    evidence=data.get("evidence", ""),
                )
            )

        total_nodes = G.number_of_nodes()
        total_edges = G.number_of_edges()
        
        # Calculate connected components and density on undirected copy
        G_undirected = G.to_undirected()
        num_components = nx.number_connected_components(G_undirected) if total_nodes > 0 else 0
        density = round(nx.density(G), 4) if total_nodes > 1 else 0.0

        return ThreatGraphData(
            total_nodes=total_nodes,
            total_edges=total_edges,
            connected_components_count=num_components,
            density=density,
            nodes=nodes_list,
            edges=edges_list,
        )
