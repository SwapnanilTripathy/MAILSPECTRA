import React from 'react';
import { renderToStaticMarkup as render } from 'react-dom/server';
import assert from 'node:assert/strict';
import RelayHopsView from '../src/components/investigation/RelayHopsView';
import DnsRdapView from '../src/components/investigation/DnsRdapView';
import ThreatGraphView from '../src/components/investigation/ThreatGraphView';
import CampaignAttributionView from '../src/components/investigation/CampaignAttributionView';
import ObservablesView from '../src/components/investigation/ObservablesView';
import VerdictBanner from '../src/components/investigation/VerdictBanner';
import IntelligencePage from '../src/pages/IntelligencePage';
import fixture from './fixtures/analysis.json';

export function checkContracts() {
  const intelligence = render(<IntelligencePage />);
  assert.match(intelligence, /not a maliciousness score or DGA classifier/);
  assert.doesNotMatch(intelligence, /LIKELY ALGORITHMIC DGA|STANDARD LEXICAL DISTRIBUTION/);
  const relay = render(<RelayHopsView relayPath={fixture.relay_chain} />);
  assert.match(relay, /mx\.example\.test/);
  assert.match(relay, /2026-01-01T00:00:00/);
  const dns = render(<DnsRdapView infrastructureIntel={fixture.infrastructure_intelligence} />);
  assert.match(dns, /192\[\.\]0\[\.\]2\[\.\]10/);
  assert.match(dns, /fixture-mx\.example\.test/);
  assert.match(dns, /UNAVAILABLE/);
  const graph = render(<ThreatGraphView threatGraph={fixture.threat_graph} />);
  assert.match(graph, /DOMAIN/);
  assert.match(graph, />0\.125</);
  const campaign = render(<CampaignAttributionView campaignCorrelations={fixture.campaign_correlations} attributionSupport={fixture.attribution_support} />);
  assert.match(campaign, /CASE-RELATED/);
  assert.match(campaign, /Temporal context unavailable/);
  const withContext = render(<CampaignAttributionView campaignCorrelations={[{related_case_id:'CASE-HASH',shared_values:{attachment_hashes:['a'.repeat(64)]},temporal_context:{elapsed_days:2,window_days:90}}]} />);
  assert.match(withContext, new RegExp('a'.repeat(64)));
  assert.match(withContext, /2.00 days apart; 90-day window/);
  assert.match(campaign, /0%/); // Must preserve a real zero, not invent an 80% fallback.
  const attachments = render(<ObservablesView observables={[]} attachments={fixture.attachments} />);
  assert.match(attachments, /Attachments \(1\)/);
  const missing = render(<VerdictBanner analysis={{}} />);
  assert.match(missing, /Unavailable/);
  assert.match(missing, /UNKNOWN/);
  assert.match(missing, /Model unavailable; rule fallback/);
  const legacy = render(<VerdictBanner analysis={{authentication:{spf_result:'fail',dkim_result:'fail',dmarc_result:'fail',raw_authentication_results:['attacker.test; spf=fail; dkim=fail; dmarc=fail']},threat_assessment:{risk_score:80,classification:'PHISHING',confidence:1}}} />);
  assert.match(legacy, /LEGACY \/ PRELIMINARY UNVERIFIED/);
  const zero = render(<VerdictBanner analysis={{risk_assessment:{risk_score:0,classification:'LEGITIMATE',severity:'INFORMATIONAL',model_confidence:0},threat_assessment:{risk_score:80,classification:'PHISHING'}}} />);
  assert.match(zero, /Canonical assessment/);
  assert.match(zero, /LEGITIMATE/);
  assert.doesNotMatch(zero, /PHISHING|LEGACY \/ PRELIMINARY/);
  assert.match(zero, />0<\/span>/);
  console.log('10 frontend contract render checks passed');
}
