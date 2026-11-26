import { createElement, type ComponentProps } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { ApiError } from '../api';
import { initialOrg, OrgPickerView, parseStaffOrgs, type StaffOrg } from './OrgPicker';

const staff: StaffOrg = { id: 's', name: 'Staff', kind: 'staff', status: 'active', billingRef: '', seatsUsed: 1, maxSeats: 0 };

describe('org picker', () => {
  it('starts in the first org the finder answers', async () => {
    expect(await initialOrg(() => Promise.resolve([staff]))).toEqual({ org: staff, error: null });
  });

  // The admin pages wait for a selection; no failure may leave them waiting for ever.
  it('leaves no selection, and the pages free, when there is none to make', async () => {
    expect(await initialOrg(() => Promise.reject(new ApiError(404, { error: 'not_found' })))).toEqual({ org: null, error: null });
    expect(await initialOrg(() => Promise.reject(new ApiError(403, { error: 'forbidden' })))).toEqual({ org: null, error: 'forbidden' });
    expect(await initialOrg(() => Promise.reject(new Error('offline')))).toEqual({ org: null, error: 'offline' });
    expect(await initialOrg(() => Promise.resolve([]))).toEqual({ org: null, error: 'No staff organisation found.' });
  });

  it('keeps search and selectable results visible after a failed first lookup', async () => {
    const { org, error } = await initialOrg(() => Promise.reject(new Error('offline')));
    const render = (state: Pick<ComponentProps<typeof OrgPickerView>, 'found' | 'busy' | 'error'>) =>
      renderToStaticMarkup(createElement(OrgPickerView, {
        current: org, query: 'staff', onQuery: () => {}, onSearch: () => {}, onSelect: () => {}, ...state,
      }));

    expect(render({ found: null, busy: false, error })).toContain('offline');
    expect(render({ found: null, busy: true, error: null })).toContain('Find an organisation');
    expect(render({ found: [staff], busy: false, error: null })).toMatch(/<button[^>]+class="secondary-btn">Work in this org<\/button>/);
    expect(render({ found: [], busy: false, error: null })).toContain('No organisation matches.');
    expect(render({ found: null, busy: false, error: null })).toBe('');
  });

  it('refuses a malformed list', () => {
    expect(parseStaffOrgs({ orgs: [{ ...staff }] })).toEqual([staff]);
    for (const bad of [null, {}, { orgs: [{ id: 1 }] }]) expect(() => parseStaffOrgs(bad)).toThrow();
  });
});
