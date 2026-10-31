import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { ClientName, ClientRowActions, launcherChanges } from './AdminClients';
import type { OAuthClient } from '../types';

const client: OAuthClient = {
  id: 'kymessage', clientName: 'KyMessages console', clientType: 'confidential', redirectUris: [], allowedScopes: [],
  postLogoutRedirectUris: [], launcherName: '', launcherAudience: '', enabled: true, createdAt: '',
};
const none = () => {};
const actions = (html: string) => [...html.matchAll(/class="row-action[^"]*"[^>]*>(?:<svg[\s\S]*?<\/svg>)?([^<]+)/g)].map((m) => m[1]);
const row = (c: OAuthClient) => renderToStaticMarkup(<ClientRowActions client={c} onManage={none} onLauncher={none} onRotate={none} onDelete={none} />);

describe('client name', () => {
  it('is a button that opens Manage for an administrator', () => {
    expect(renderToStaticMarkup(<ClientName client={client} onManage={none} />))
      .toBe('<button type="button" class="cell-link"><span class="sr-only">Manage </span>KyMessages console</button>');
  });
  it('stays text without Manage', () => {
    expect(renderToStaticMarkup(<ClientName client={client} />)).toBe('KyMessages console');
  });
});

describe('client row actions', () => {
  it('open from a quiet ⋯ button, with no outlined Manage button', () => {
    const html = row(client);
    expect(html).toMatch(/<button type="button" class="icon-btn sm" popover[Tt]arget="[^"]+" aria-label="More actions for KyMessages console"><svg[^>]*aria-hidden="true"/);
    expect(html).not.toContain('secondary-btn');
  });
  it('lead with Manage and keep every other action, delete last', () => {
    expect(actions(row(client))).toEqual(['Manage', 'Launcher card', 'Rotate secret', 'Delete client']);
    expect(actions(row({ ...client, clientType: 'public' }))).toEqual(['Manage', 'Launcher card', 'Delete client']);
  });
});

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
