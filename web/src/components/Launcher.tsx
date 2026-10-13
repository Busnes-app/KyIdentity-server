import React, { useState } from 'react';
import { ExternalLink } from 'lucide-react';
import type { Application } from '../types';
import type { Arranged } from '../launcherLayout';
import { faviconUrl } from '../favicon';
import { launcherIcon } from '../launcherIcons';

/** Uploaded icons are named "icon:<id>" and served by the API; built-ins are drawn inline. */
export function uploadedIconUrl(iconName: string): string | undefined {
  const id = iconName.startsWith('icon:') ? iconName.slice(5) : '';
  return /^[0-9a-f-]{36}$/.test(id) ? `/api/icons/${id}` : undefined;
}

/** Key it by iconName so a changed icon gets a fresh attempt at its image. */
export const AppIcon: React.FC<{ app: Application; size?: number }> = ({ app, size = 20 }) => {
  const [failed, setFailed] = useState(false);
  const Icon = launcherIcon(app.iconName) ?? ExternalLink;
  const image = app.iconName === 'favicon' ? faviconUrl(app.url) : uploadedIconUrl(app.iconName);
  return (
    <span className="app-icon">
      {image && !failed ? (
        <img className="app-favicon" src={image} alt="" referrerPolicy="no-referrer" onError={() => setFailed(true)} />
      ) : (
        <Icon size={size} />
      )}
    </span>
  );
};

const link = { target: '_blank', rel: 'noopener noreferrer' } as const;

export const LauncherView: React.FC<{ arranged: Arranged; onUnhide: (key: string) => void }> = ({
  arranged,
  onUnhide,
}) => {
  const { layout, groups, hidden } = arranged;
  const [dock, ...rest] = layout === 'dock' ? groups : [];
  return (
    <>
      {layout === 'tiles' &&
        groups.map((g, i) => (
          <section key={i} className="launcher-group">
            <h2 className="launcher-group-title">{g.name}</h2>
            <ul className="launcher-tiles">
              {g.apps.map((app) => (
                <li key={app.key}>
                  <a href={app.url} {...link} className="launcher-tile" title={app.description}>
                    <AppIcon key={app.iconName} app={app} />
                    {app.name}
                  </a>
                </li>
              ))}
            </ul>
          </section>
        ))}
      {dock && (
        <>
          <ul className="launcher-dock" aria-label={dock.name}>
            {dock.apps.map((app) => (
              <li key={app.key}>
                <a href={app.url} {...link} title={app.description}>
                  <AppIcon key={app.iconName} app={app} size={26} />
                  {app.name}
                </a>
              </li>
            ))}
          </ul>
          <div className="launcher-cols">
            {rest.map((g, i) => (
              <section key={i}>
                <h2 className="launcher-group-title">{g.name}</h2>
                <ul>
                  {g.apps.map((app) => (
                    <li key={app.key}>
                      <a href={app.url} {...link} className="launcher-item">
                        <AppIcon key={app.iconName} app={app} size={16} />
                        <span>
                          <b>{app.name}</b>
                          {app.description && <small>{app.description}</small>}
                        </span>
                      </a>
                    </li>
                  ))}
                </ul>
              </section>
            ))}
          </div>
        </>
      )}
      {hidden.length > 0 && (
        <div className="launcher-hidden">
          <span>{hidden.length} hidden:</span>
          {hidden.map((app) => (
            <button key={app.key} type="button" className="launcher-chip" onClick={() => onUnhide(app.key)} title="Show again">
              {app.name}
            </button>
          ))}
        </div>
      )}
    </>
  );
};
