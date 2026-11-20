import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { SuiteThemeSelect, parseSuiteSettings, splitDomains } from './AdminSuiteSettings';

describe('suite settings', () => {
  it('parses the admin response and refuses anything else', () => {
    expect(parseSuiteSettings({ emailDomains: ['example.com'], defaultTheme: 'ocean-pair' })).toEqual({ emailDomains: ['example.com'], defaultTheme: 'ocean-pair' });
    for (const bad of [null, {}, { emailDomains: 'example.com', defaultTheme: 'x' }, { emailDomains: [1], defaultTheme: 'x' }, { emailDomains: [] }]) {
      expect(() => parseSuiteSettings(bad)).toThrow();
    }
  });

  it('splits domains on lines, commas and spaces and drops blanks', () => {
    expect(splitDomains(' example.com\n\nmail.example.org, other.example \n')).toEqual(['example.com', 'mail.example.org', 'other.example']);
    expect(splitDomains('  \n')).toEqual([]);
  });
  it('lists "no suite default" once, first, selected when none is set', () => {
    const render = (value: string) => renderToStaticMarkup(createElement(SuiteThemeSelect, { value, disabled: false, onChange: () => {} }));
    const fresh = render('system');
    expect(fresh.match(/value="system"/g)).toHaveLength(1);
    expect(fresh).toMatch(/^<select[^>]*><option value="system" selected="">No suite default \(Busnes, follows device\)<\/option><optgroup label="Busnes">/);
    // Busnes keeps its fixed halves; every other pair keeps all three choices.
    expect(fresh.match(/<option /g)).toHaveLength(18);
    expect(render('ocean-pair')).toContain('<option value="ocean-pair" selected="">Ocean, follows device</option>');
  });
});
