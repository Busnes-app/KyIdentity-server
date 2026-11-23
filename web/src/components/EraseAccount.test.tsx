import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { ExportLinks, confirmsAddress, eraseAddress, eraseSummary, parseEraseScope } from './EraseAccount';
import { parseEnrollmentStatus } from '../parsers';

describe('Delete everything', () => {
  it('parses the options answer and refuses anything else', () => {
    expect(parseEraseScope({ holder: true, otherMembers: 2 })).toEqual({ holder: true, otherMembers: 2 });
    for (const bad of [null, {}, { holder: 'yes', otherMembers: 0 }, { holder: false }]) {
      expect(() => parseEraseScope(bad)).toThrow();
    }
  });

  it('says what each click deletes', () => {
    expect(eraseSummary({ holder: false, otherMembers: 0 })).toMatch(/^Deletes your account .*organisation keeps their data/);
    expect(eraseSummary({ holder: true, otherMembers: 0 })).toMatch(/right away/);
    expect(eraseSummary({ holder: true, otherMembers: 1 })).toMatch(/The other member has 7 days to export/);
    expect(eraseSummary({ holder: true, otherMembers: 3 })).toMatch(/The other 3 members have 7 days/);
  });

  it('reads exportOnly only when the server says true', () => {
    const base = { required: false, allowedMethods: ['totp'], deadline: 0, enrolled: false, restricted: false };
    expect(parseEnrollmentStatus(base)).toEqual(base);
    expect(parseEnrollmentStatus({ ...base, exportOnly: true })).toEqual({ ...base, exportOnly: true });
    expect(parseEnrollmentStatus({ ...base, exportOnly: 'yes' })).toEqual(base);
  });

  it('never shows a failed or loading app list as nothing to export', () => {
    const render = (apps: Parameters<typeof ExportLinks>[0]['apps']) => renderToStaticMarkup(createElement(ExportLinks, { apps, retry: () => {} }));
    expect(render('loading')).toContain('Loading your apps');
    expect(render('failed')).toContain('could not be loaded');
    expect(render('failed')).toContain('Try again');
    for (const state of ['loading', 'failed'] as const) expect(render(state)).not.toContain('no apps');
    expect(render([])).toContain('You have no apps to export from.');
    expect(render([{ id: 'kypost', key: 'client:kypost', name: 'KyPost', url: 'https://mail.example.test/', iconName: '', enabled: true }]))
      .toContain('<a href="https://mail.example.test/" target="_blank" rel="noopener noreferrer">Export from KyPost</a>');
  });

  it('asks for the mailbox address when there is one, else the sign-in email', () => {
    expect(eraseAddress({ email: 'alex@home.example', mailboxAddress: 'alex@mail.example' })).toBe('alex@mail.example');
    expect(eraseAddress({ email: 'alex@home.example' })).toBe('alex@home.example');
  });

  it('confirms only the exact address, and never an empty one', () => {
    expect(confirmsAddress('  Alex@Example.test ', 'alex@example.test')).toBe(true);
    expect(confirmsAddress('alex@example.tes', 'alex@example.test')).toBe(false);
    expect(confirmsAddress('', '')).toBe(false);
    expect(confirmsAddress('   ', '')).toBe(false);
  });
});
