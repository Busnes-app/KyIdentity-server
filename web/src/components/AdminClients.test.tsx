import { describe, expect, it } from 'vitest';
import { launcherChanges } from './AdminClients';
import type { OAuthClient } from '../types';

const client: OAuthClient = {
  id: 'kymessage', clientName: 'KyMessages console', clientType: 'confidential', redirectUris: [], allowedScopes: [],
  postLogoutRedirectUris: [], launcherName: '', launcherAudience: '', enabled: true, createdAt: '',
};

describe('launcherChanges', () => {
  it('sends nothing when the admin changed nothing, so unset values stay unset', () => {
    expect(launcherChanges(client, '', 'everyone')).toEqual({});
    expect(launcherChanges({ ...client, launcherName: 'Chat', launcherAudience: 'admins' }, ' Chat ', 'admins')).toEqual({});
  });

  it('sends only the changed fields', () => {
    expect(launcherChanges(client, 'Console', 'everyone')).toEqual({ launcherName: 'Console' });
    expect(launcherChanges(client, '', 'admins')).toEqual({ launcherAudience: 'admins' });
    expect(launcherChanges({ ...client, launcherName: 'Chat' }, '  ', 'everyone')).toEqual({ launcherName: '' });
  });
});
