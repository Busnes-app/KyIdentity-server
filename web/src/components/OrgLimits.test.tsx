import { describe, expect, it } from 'vitest';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { parseOrgLimits } from './OrgLimits';
import { HolderExportLink, parseOrgExportStatus } from './EraseAccount';

const limits = { max_seats: 3, seats_used: 2, storage_bytes: 1073741824, storage_per_seat_bytes: 0, pool_bytes: 1073741824, used_bytes: 100, revision: 1, org_revision: 2, status_reason: '', restore_generation: '', storage_usage: { kydrive: { used_bytes: 100, reported_at: 1000 } } };
describe('organisation limits and directory export', () => {
  it('accepts exact reported usage and rejects malformed limits at the boundary', () => {
    expect(parseOrgLimits(limits)).toEqual(limits);
    for (const bad of [null, {}, { ...limits, max_seats: NaN }, { ...limits, org_revision: -1 }, { ...limits, used_bytes: -1 }, { ...limits, storage_usage: { kydrive: { used_bytes: '100', reported_at: 1000 } } }]) expect(() => parseOrgLimits(bad)).toThrow();
  });
  it('shows a dated deletion banner and direct directory download, separate from app content', () => {
    expect(parseOrgExportStatus({ deleteAfter: 1900000000 })).toBe(1900000000);
    for (const v of [{}, { deleteAfter: 'tomorrow' }, { deleteAfter: 0 }]) expect(() => parseOrgExportStatus(v)).toThrow();
    const html = renderToStaticMarkup(createElement(HolderExportLink, { deadline: 1900000000 }));
    expect(html).toContain('scheduled for permanent deletion');
    expect(html).toContain('href="/api/user/org-export"');
    expect(html).toContain('App content is exported from each app separately');
  });
});
