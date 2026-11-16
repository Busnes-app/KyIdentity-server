import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { SuiteGroupForm } from './SuiteGroupSettings';
import { parseSuiteGroupSettings } from '../parsers';

const apps = [{ id: 'kycalendar', enabled: true }, { id: 'kydrive', enabled: true }, { id: 'kymessage', enabled: true }, { id: 'kypost', enabled: false }];
const none = () => {};

describe('suite group settings', () => {
  it('parse the admin response and refuse a malformed one', () => {
    expect(parseSuiteGroupSettings({ enabled: true, slug: 'sales', apps })).toEqual({ enabled: true, slug: 'sales', apps });
    expect(() => parseSuiteGroupSettings({ enabled: true })).toThrow();
  });
  it('show only the group switch while off', () => {
    const html = renderToStaticMarkup(<SuiteGroupForm settings={{ enabled: false, apps }} busy={false} onSave={none} />);
    expect(html).toContain('Create shared resources for this group');
    expect(html).not.toContain('KyDrive workspace');
    expect(html).toContain('nothing is deleted');
  });
  it('list every app with its state while on', () => {
    const html = renderToStaticMarkup(<SuiteGroupForm settings={{ enabled: true, slug: 'sales', apps }} busy={false} onSave={none} />);
    for (const label of ['KyCalendar group calendar', 'KyDrive workspace', 'KyMessages room', 'KyPost distribution list']) expect(html).toContain(label);
    expect(html).toContain('Address name: sales.');
    expect((html.match(/checked=""/g) ?? []).length).toBe(4);
  });
});
