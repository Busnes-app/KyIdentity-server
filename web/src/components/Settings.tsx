import React from 'react';
import { User } from '../types';
import { SETTINGS_SECTIONS, SettingsSection } from '../route';
import { PageHead } from './PageHead';
import { DeviceSettings } from './DeviceSettings';
import { Appearance } from './Appearance';

const INTRO: Record<SettingsSection, React.ReactNode> = {
  account: <>Your password, passkeys and codes, and where you are signed in. Phones that approve sign-ins are under <a href="#/settings/devices">Phones &amp; apps</a>.</>,
  devices: 'Pair KyAuth on a phone to approve sign-ins with a tap. A phone you allow can also sign you in to suite apps.',
  appearance: 'Pick a palette and how it handles light and dark. Match system switches with your device’s setting; Light or Dark keeps one. Your choice applies straight away and is saved in this browser only.',
};

/** Settings: the page head, one tab per section, then the open section. */
export const Settings: React.FC<{ section: SettingsSection; user: User; onUserUpdate: () => void }> = ({ section, user, onUserUpdate }) => {
  const label = SETTINGS_SECTIONS.find(([id]) => id === section)![1];
  return (
    <>
      <PageHead title="Settings" lede="Your account, the phones that approve your sign-ins, and how KyIdentity looks." />
      <nav className="ky-settings-tabs" aria-label="Settings sections">
        {SETTINGS_SECTIONS.map(([id, name]) => (
          <a key={id} className="ky-nav-item" href={`#/settings/${id}`} aria-current={id === section ? 'page' : undefined}>{name}</a>
        ))}
      </nav>
      {/* Not a <section>: the pre-bundle /css/styles.css pads every section like a landing page. */}
      <div role="region" aria-label={label}>
        <p className="settings-intro">{INTRO[section]}</p>
        {section === 'appearance' ? <Appearance /> : <DeviceSettings key={section} section={section} user={user} onUserUpdate={onUserUpdate} />}
      </div>
    </>
  );
};
