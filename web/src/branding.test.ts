import { describe, expect, it } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { createElement } from 'react';
import { parseBranding } from './branding';
import { AuthBrand } from './components/AuthFrame';

describe('branding', () => {
  it('accepts only the server-issued logo path as an image source', () => {
    expect(parseBranding({ name: 'Acme', logoUrl: '/api/branding/logo?v=0123456789abcdef' }).logoUrl).toBe('/api/branding/logo?v=0123456789abcdef');
    for (const logoUrl of ['https://evil.test/x.png', 'javascript:alert(1)', 'data:image/svg+xml,<svg/>', '//evil.test/api/branding/logo?v=0123456789abcdef', '/api/branding/logo?v=0123456789abcdef&x=1']) {
      expect(parseBranding({ name: 'Acme', logoUrl }).logoUrl).toBe('');
    }
    expect(() => parseBranding({ name: 1, logoUrl: '' })).toThrow();
  });

  it('shows KyIdentity until an organisation is set, then its name and logo', () => {
    const plain = renderToStaticMarkup(createElement(AuthBrand, { branding: { name: '', logoUrl: '' } }));
    expect(plain).toContain('<h1>KyIdentity</h1>');
    expect(plain).toContain('src="/app-icon.png"');
    const acme = renderToStaticMarkup(createElement(AuthBrand, { branding: { name: 'Acme <b>Holdings</b>', logoUrl: '/api/branding/logo?v=0123456789abcdef' } }));
    // React escapes the name: it is text, never markup.
    expect(acme).toContain('<h1>Acme &lt;b&gt;Holdings&lt;/b&gt;</h1>');
    expect(acme).toContain('class="brand-logo" src="/api/branding/logo?v=0123456789abcdef"');
    expect(acme).toContain('Sign in with KyIdentity');
  });
});
