import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { SystemRowActions } from './AdminSystems';
import { UrlCell } from './UrlCell';
import type { PairedSystem } from '../types';

const system: PairedSystem = {
  id: 's1', name: 'KyDrive', systemType: 'scim', callbackUrl: 'https://drive.urlxl.com/scim/v2', status: 'active',
  createdAt: '', groupsEnabled: false, reconcileHours: 0, provisioningHold: false,
};
const none = () => {};
const actions = (html: string) => [...html.matchAll(/class="row-action[^"]*"[^>]*>(?:<svg[\s\S]*?<\/svg>)?([^<]+)/g)].map((m) => m[1]);
const row = (s: PairedSystem) => renderToStaticMarkup(<SystemRowActions system={s} onConnection={none} onDeliveries={none} onProvisioning={none} onTest={none} onResync={none} onDelete={none} />);

describe('suite sync row actions', () => {
  it('sit behind one ⋯ button, with no row of outlined buttons', () => {
    const html = row(system);
    expect(html).toMatch(/<button type="button" class="icon-btn sm" popover[Tt]arget="[^"]+" aria-label="More actions for KyDrive"><svg[^>]*aria-hidden="true"/);
    expect(html).not.toContain('secondary-btn');
  });
  it('give every type the same menu shape, SCIM adding its connection items, Disconnect last', () => {
    expect(actions(row(system))).toEqual(['Connection settings', 'Deliveries', 'Provisioning', 'Test connection', 'Resync directory', 'Disconnect']);
    expect(actions(row({ ...system, systemType: 'suite_webhook' }))).toEqual(['Deliveries', 'Provisioning', 'Resync directory', 'Disconnect']);
  });
  it('offer Review connection for a legacy type and hold its resync', () => {
    const html = row({ ...system, systemType: 'custom' });
    expect(actions(html)[0]).toBe('Review connection');
    expect(html).toMatch(/<button type="button" class="row-action" disabled=""[^>]*>[\s\S]*?Resync directory/);
  });
});

describe('url cell', () => {
  it('truncates one line and keeps every URL in the title', () => {
    const html = renderToStaticMarkup(<UrlCell values={['https://yard.urlxl.us:30443/api/sso/kyidentity/callback', 'https://yard.urlxl.com/cb']} />);
    expect(html).toBe('<span class="cell-stack"><span class="cell-truncate font-mono" title="https://yard.urlxl.us:30443/api/sso/kyidentity/callback\nhttps://yard.urlxl.com/cb">https://yard.urlxl.us:30443/api/sso/kyidentity/callback</span><span class="cell-meta">+1 more</span></span>');
  });
});
