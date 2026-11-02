import { describe, expect, it } from 'vitest';
import { listCell } from './listCell';

describe('listCell', () => {
  it('shows one value whole in the tooltip, with no note', () => {
    const url = 'https://recovery.urlxl.us:30443/api/installer/directory';
    expect(listCell([url])).toEqual({ first: url, more: '', title: url });
  });
  it('leads with the first value, counts the rest and lists all of them in the tooltip', () => {
    const uris = ['https://yard.urlxl.us:30443/cb', 'https://yard.urlxl.com/cb', 'http://127.0.0.1:8088/cb'];
    expect(listCell(uris)).toEqual({ first: uris[0], more: '+2 more', title: uris.join('\n') });
  });
  it('is empty for no values and skips blank ones', () => {
    expect(listCell([])).toEqual({ first: '', more: '', title: '' });
    expect(listCell(['', ' ', 'https://a.example/cb'])).toEqual({ first: 'https://a.example/cb', more: '', title: 'https://a.example/cb' });
  });
});
