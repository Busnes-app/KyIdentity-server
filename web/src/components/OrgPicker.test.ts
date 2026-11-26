import { describe, expect, it } from 'vitest';
import { ApiError } from '../api';
import { initialOrg, parseStaffOrgs, type StaffOrg } from './OrgPicker';

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

  it('refuses a malformed list', () => {
    expect(parseStaffOrgs({ orgs: [{ ...staff }] })).toEqual([staff]);
    for (const bad of [null, {}, { orgs: [{ id: 1 }] }]) expect(() => parseStaffOrgs(bad)).toThrow();
  });
});
