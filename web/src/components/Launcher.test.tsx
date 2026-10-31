import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { AppIcon } from './Launcher';

const icon = (iconName: string) =>
  renderToStaticMarkup(<AppIcon app={{ id: 'kydrive', key: 'client:kydrive', name: 'KyDrive', url: 'https://drive.example.com/', iconName, enabled: true }} />);

describe('AppIcon', () => {
  it('draws a bundled suite icon from this origin', () => {
    expect(icon('suite:kydrive')).toContain('src="/suite-icons/kydrive.png"');
  });

  it('keeps an explicit lucide icon or the favicon', () => {
    expect(icon('globe')).not.toContain('<img');
    expect(icon('favicon')).toContain('src="https://drive.example.com/favicon.ico"');
  });

  it('never turns an unlisted suite name into a URL', () => {
    expect(icon('suite:../x')).not.toContain('<img');
  });
});
