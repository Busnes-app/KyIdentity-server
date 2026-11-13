import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { AdminOfficeNetworks, networksToText, textToNetworks } from './AdminOfficeNetworks';
import { parseRateLimitNetworks } from '../parsers';

describe('office networks', () => {
  it('edits one network per line and sends a comma-separated list', () => {
    expect(networksToText('203.0.113.0/24,2001:db8:1::/48')).toBe('203.0.113.0/24\n2001:db8:1::/48');
    expect(networksToText('')).toBe('');
    expect(textToNetworks(' 203.0.113.0/24\n\n2001:db8:1::/48 , 198.51.100.7\n')).toBe('203.0.113.0/24,2001:db8:1::/48,198.51.100.7');
  });
  it('parses the server reply strictly', () => {
    expect(parseRateLimitNetworks({ networks: '203.0.113.0/24', environment: '', exempted: 3 })).toEqual({ networks: '203.0.113.0/24', environment: '', exempted: 3 });
    expect(() => parseRateLimitNetworks({ networks: '', environment: '' })).toThrow();
  });
  it('warns to list only networks you control', () => {
    const html = renderToStaticMarkup(<AdminOfficeNetworks />);
    expect(html).toContain('Office networks');
    expect(html).toContain('Networks that skip the per-address limit, one per line');
    expect(html).toContain('never add guest Wi-Fi, a VPN provider or your reverse proxy');
  });
});
