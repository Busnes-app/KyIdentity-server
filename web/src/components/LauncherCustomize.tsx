import React, { useEffect, useMemo, useRef, useState } from 'react';
import { ArrowDown, ArrowUp, GripVertical, Plus, X } from 'lucide-react';
import type { Application, LauncherPrefs } from '../types';
import {
  MAX_GROUPS,
  MAX_GROUP_NAME,
  Slot,
  addGroup,
  deleteGroup,
  forSave,
  moveApp,
  renameGroup,
  shiftApp,
} from '../launcherLayout';
import { AppIcon } from './Launcher';

interface Props {
  apps: Application[];
  initial: LauncherPrefs;
  onCancel: () => void;
  onSave: (prefs: LauncherPrefs) => Promise<void>;
  onReset: () => Promise<void>;
}

const LAYOUTS = [
  ['tiles', 'Tiles', 'Every group as a grid with names, icons and descriptions.'],
  ['dock', 'Dock + list', 'First group as large icons; the rest as a compact list with descriptions.'],
] as const;

/** Edits stay local until Done, so Cancel really cancels. */
export const LauncherCustomize: React.FC<Props> = ({ apps, initial, onCancel, onSave, onReset }) => {
  const [draft, setDraft] = useState(initial);
  const [busy, setBusy] = useState(false);
  const [dragKey, setDragKey] = useState<string | null>(null);
  const [dropSlot, setDropSlot] = useState<Slot | null>(null);
  // Reordering moves DOM nodes, which drops focus; put it back on the control just used.
  const refocus = useRef<string | null>(null);
  const root = useRef<HTMLDivElement>(null);

  const byKey = useMemo(() => new Map(apps.map((a) => [a.key, a])), [apps]);
  const visible = useMemo(() => new Set(byKey.keys()), [byKey]);
  const shown = (keys: string[]) => keys.filter((k) => visible.has(k));
  const dockIndex = draft.layout === 'dock' ? draft.groups.findIndex((g) => shown(g.apps).length) : -1;

  useEffect(() => {
    if (!refocus.current) return;
    root.current?.querySelector<HTMLElement>(refocus.current)?.focus();
    refocus.current = null;
  }, [draft]);

  const run = async (action: () => Promise<void>) => {
    setBusy(true);
    try {
      await action();
    } finally {
      setBusy(false);
    }
  };

  const slotOptions = draft.groups.map((g, i) => (
    <option key={i} value={i}>
      {g.name.trim() || 'Untitled'}
    </option>
  ));

  const row = (key: string, slot: Slot) => {
    const app = byKey.get(key);
    if (!app) return null;
    const sel = `[data-key="${CSS.escape(key)}"]`;
    return (
      <li
        key={key}
        data-key={key}
        className={`launcher-edit-row${dragKey === key ? ' dragging' : ''}`}
        draggable
        onDragStart={(e) => {
          e.dataTransfer.effectAllowed = 'move';
          e.dataTransfer.setData('text/plain', key);
          setDragKey(key);
        }}
        onDragEnd={() => {
          setDragKey(null);
          setDropSlot(null);
        }}
      >
        <GripVertical size={16} className="launcher-grip" aria-hidden />
        <AppIcon key={app.iconName} app={app} size={16} />
        <span className="launcher-edit-name">{app.name}</span>
        {([-1, 1] as const).map((dir) => (
          <button
            key={dir}
            type="button"
            className="icon-btn"
            data-dir={dir}
            aria-label={`Move ${app.name} ${dir < 0 ? 'up' : 'down'}`}
            onClick={() => {
              refocus.current = `${sel} [data-dir="${dir}"]`;
              setDraft(shiftApp(draft, key, dir, visible));
            }}
          >
            {dir < 0 ? <ArrowUp size={14} /> : <ArrowDown size={14} />}
          </button>
        ))}
        <select
          className="launcher-edit-select"
          aria-label={`Group for ${app.name}`}
          value={slot}
          onChange={(e) => {
            refocus.current = `${sel} select`;
            setDraft(moveApp(draft, key, e.target.value === 'hidden' ? 'hidden' : Number(e.target.value)));
          }}
        >
          {slotOptions}
          <option value="hidden">Hidden</option>
        </select>
      </li>
    );
  };

  const column = (slot: Slot, keys: string[], header: React.ReactNode, footer?: React.ReactNode) => (
    <section
      className={`launcher-edit-col${slot === 'hidden' ? ' hidden-col' : ''}${dropSlot === slot ? ' drop' : ''}`}
      onDragOver={(e) => {
        if (!dragKey) return;
        e.preventDefault();
        setDropSlot(slot);
      }}
      onDrop={(e) => {
        e.preventDefault();
        const before = (e.target as Element).closest('[data-key]')?.getAttribute('data-key') ?? undefined;
        if (dragKey && before !== dragKey) setDraft(moveApp(draft, dragKey, slot, before));
        setDragKey(null);
        setDropSlot(null);
      }}
    >
      <header>{header}</header>
      <ul>{keys.map((k) => row(k, slot))}</ul>
      {shown(keys).length === 0 && <p className="text-muted launcher-edit-empty">Drop apps here.</p>}
      {footer}
    </section>
  );

  return (
    <div ref={root}>
      <div className="page-header">
        <h1 className="page-title">Customize launcher</h1>
        <div className="launcher-actions">
          <button
            type="button"
            className="secondary-btn sm"
            disabled={draft.groups.length >= MAX_GROUPS}
            onClick={() => {
              refocus.current = `[data-group="${draft.groups.length}"]`;
              setDraft(addGroup(draft));
            }}
          >
            <Plus size={14} /> New group
          </button>
          <button
            type="button"
            className="secondary-btn sm"
            disabled={busy}
            onClick={() => window.confirm('Reset your launcher to the default layout?') && run(onReset)}
          >
            Reset to default
          </button>
          <button type="button" className="secondary-btn sm" disabled={busy} onClick={onCancel}>
            Cancel
          </button>
          <button type="button" className="primary-btn sm" disabled={busy} onClick={() => run(() => onSave(forSave(draft)))}>
            Done
          </button>
        </div>
      </div>

      <fieldset className="launcher-layout">
        <legend className="form-label">Layout</legend>
        {LAYOUTS.map(([value, label, hint]) => (
          <label key={value}>
            <input
              type="radio"
              name="launcher-layout"
              value={value}
              checked={draft.layout === value}
              onChange={() => setDraft({ ...draft, layout: value })}
            />
            <span>
              <b>{label}</b>
              <small>{hint}</small>
            </span>
          </label>
        ))}
      </fieldset>

      <div className="launcher-edit">
        {draft.groups.map((g, i) =>
          column(
            i,
            g.apps,
            <>
              <input
                className="launcher-group-name"
                data-group={i}
                value={g.name}
                maxLength={MAX_GROUP_NAME}
                aria-label="Group name"
                onChange={(e) => setDraft(renameGroup(draft, i, e.target.value))}
              />
              {i === dockIndex && <span className="launcher-badge">Dock</span>}
              <button
                type="button"
                className="icon-btn"
                aria-label={`Delete group ${g.name}`}
                title="Delete group (its apps move to Hidden)"
                onClick={() => setDraft(deleteGroup(draft, i))}
              >
                <X size={14} />
              </button>
            </>,
          ),
        )}
        {column(
          'hidden',
          draft.hidden,
          <b>Hidden</b>,
          <p className="text-muted launcher-edit-empty">
            Hidden apps stay available to you. Hiding is not the same as removing access.
          </p>,
        )}
      </div>
    </div>
  );
};
