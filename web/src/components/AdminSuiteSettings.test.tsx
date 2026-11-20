import { describe, expect, it } from 'vitest';
import { parseSuiteSettings, splitDomains } from './AdminSuiteSettings';

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
});
