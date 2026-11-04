import type { ReactNode } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';
import { DelegationEditor } from './DelegationEditor';
import type { User } from '../types';

// The real Modal mounts its body only once a browser opens the dialog.
vi.mock('./Modal', () => ({ Modal: ({ children }: { children: ReactNode }) => <>{children}</> }));

describe('delegation editor', () => {
  it('offers nothing to change or save until the current delegations have loaded', () => {
    // Save replaces every delegation; over an unloaded form it would strip them all.
    const user = { id: 'u1', username: 'sam', role: 'user' } as User;
    const html = renderToStaticMarkup(<DelegationEditor user={user} onClose={() => {}} />);
    expect(html).not.toContain('type="checkbox"');
    expect(html).toContain('<button type="button" class="primary-btn" disabled="">Save</button>');
  });
});
