import { describe, expect, it } from 'vitest';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { parseOrgLimits } from './OrgLimits';
import {
  HolderExportLink,
  orgExportFilename,
  orgExportUrl,
  parseOrgExportContinuation,
  parseOrgExportStatus,
} from './EraseAccount';

const limits = { max_seats: 3, seats_used: 2, storage_bytes: 1073741824, storage_per_seat_bytes: 0, pool_bytes: 1073741824, used_bytes: 100, revision: 1, org_revision: 2, status_reason: '', restore_generation: '', storage_usage: { kydrive: { used_bytes: 100, reported_at: 1000 } } };
describe('organisation limits and directory export', () => {
  it('accepts exact reported usage and rejects malformed limits at the boundary', () => {
    expect(parseOrgLimits(limits)).toEqual(limits);
    for (const bad of [null, {}, { ...limits, max_seats: NaN }, { ...limits, org_revision: -1 }, { ...limits, used_bytes: -1 }, { ...limits, storage_usage: { kydrive: { used_bytes: '100', reported_at: 1000 } } }]) expect(() => parseOrgLimits(bad)).toThrow();
  });
  it('shows a dated deletion banner and directory download, separate from app content', () => {
    expect(parseOrgExportStatus({ deleteAfter: 1900000000 })).toBe(1900000000);
    for (const v of [{}, { deleteAfter: 'tomorrow' }, { deleteAfter: 0 }]) expect(() => parseOrgExportStatus(v)).toThrow();
    const html = renderToStaticMarkup(createElement(HolderExportLink, { deadline: 1900000000 }));
    expect(html).toContain('scheduled for permanent deletion');
    expect(html).toContain('Download organisation directory (JSON)');
    expect(html).toContain('App content is exported from each app separately');
  });
  it('parses partial export continuation metadata and renders next audit page action', () => {
    expect(parseOrgExportContinuation({ org: { id: 'o1' } })).toEqual({ kind: 'complete' });
    expect(parseOrgExportContinuation({ partial: true, truncated: { audit: { limit: 50000, offset: 0, next_offset: 50000 } } })).toEqual({
      kind: 'partial',
      truncatedSections: ['audit'],
      nextAuditOffset: 50000,
    });
    expect(parseOrgExportContinuation({ partial: true, truncated: { members: { limit: 50000 } } })).toEqual({
      kind: 'partial',
      truncatedSections: ['members'],
      nextAuditOffset: null,
    });
    expect(() => parseOrgExportContinuation(null)).toThrow();
    expect(orgExportUrl(0)).toBe('/api/user/org-export');
    expect(orgExportUrl(50000)).toBe('/api/user/org-export?audit_offset=50000');
    expect(orgExportFilename(0)).toBe('organisation.json');
    expect(orgExportFilename(50000)).toBe('organisation-audit-from-50000.json');

    const partialHtml = renderToStaticMarkup(createElement(HolderExportLink, {
      deadline: 1900000000,
      initialContinuation: { kind: 'partial', truncatedSections: ['audit'], nextAuditOffset: 50000 },
    }));
    expect(partialHtml).toContain('Partial export saved');
    expect(partialHtml).toContain('Download next audit page (from event 50000)');
    expect(partialHtml).toContain('audit');
  });
});
