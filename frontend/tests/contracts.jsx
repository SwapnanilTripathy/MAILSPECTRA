import React from 'react';
import { renderToStaticMarkup as render } from 'react-dom/server';
import assert from 'node:assert/strict';
import RelayHopsView from '../src/components/investigation/RelayHopsView';
import DnsRdapView from '../src/components/investigation/DnsRdapView';
import ThreatGraphView from '../src/components/investigation/ThreatGraphView';
import CampaignAttributionView from '../src/components/investigation/CampaignAttributionView';
import ObservablesView from '../src/components/investigation/ObservablesView';
import VerdictBanner from '../src/components/investigation/VerdictBanner';
import fixture from './fixtures/analysis.json';

export function checkContracts() {
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
  assert.match(campaign, /0%/); // Must preserve a real zero, not invent an 80% fallback.
  const attachments = render(<ObservablesView observables={[]} attachments={fixture.attachments} />);
  assert.match(attachments, /Attachments \(1\)/);
  const missing = render(<VerdictBanner analysis={{}} />);
  assert.match(missing, /Unavailable/);
  assert.match(missing, /UNKNOWN/);
  assert.match(missing, /Model unavailable; rule fallback/);
  console.log('6 frontend contract render checks passed');
}
