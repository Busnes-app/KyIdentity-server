import { describe, expect, it } from 'vitest';
import { auditQuery, type AuditFilter } from './components/AdminAudit';

const none: AuditFilter = { actor: '', target: '', action: '', outcome: '', from: '', to: '' };

describe('auditQuery', () => {
  // An empty query is what selects "no events recorded yet" over "no matches".
  it('is empty when nothing narrows the log', () => {
    expect(auditQuery(none)).toBe('');
    expect(auditQuery({ ...none, actor: '   ', action: '\t' })).toBe('');
  });

  it('trims text filters and keeps the outcome', () => {
    expect(auditQuery({ ...none, actor: ' bob ', action: 'oauth.', outcome: 'denied' }))
      .toBe('actor=bob&action=oauth.&outcome=denied');
  });
});
