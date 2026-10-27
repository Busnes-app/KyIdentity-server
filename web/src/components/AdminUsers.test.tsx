import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { UserRowActions } from './AdminUsers';
import type { User } from '../types';

const admin: User = { id: 'a1', username: 'admin', displayName: 'Administrator', email: 'admin@x.test', role: 'admin' };
const member: User = { id: 'u1', username: 'member', displayName: 'Member', email: 'member@x.test', role: 'user' };
const none = () => {};
const act = { groups: none, edit: none, delegate: none, resetMFA: none, sessions: none, revoke: none, link: none, offboarding: none, remove: none };
const render = (u: User, full: boolean) => renderToStaticMarkup(<UserRowActions u={u} full={full} busy={false} act={act} />);
const actions = (html: string) => [...html.matchAll(/class="row-action[^"]*"[^>]*>(?:<svg[\s\S]*?<\/svg>)?([^<]+)/g)].map((m) => m[1]);

describe('user row actions', () => {
  it('give a full administrator all nine, with delete last', () => {
    const html = render(admin, true);
    expect(html).toContain('popover="auto"');
    expect(actions(html)).toEqual(['Groups', 'Edit user', 'Delegated administration', 'Reset MFA', 'Sessions and apps',
      'Revoke sessions', 'Password reset link', 'Offboarding status', 'Delete user']);
  });

  it('render no disclosure for a delegate on an administrator row, where every action is gated away', () => {
    expect(render(admin, false)).toBe('');
  });

  it('give a delegate the five recovery actions on an ordinary row', () => {
    const html = render(member, false);
    expect(html).toContain('popover="auto"');
    expect(actions(html)).toEqual(['Reset MFA', 'Sessions and apps', 'Revoke sessions', 'Password reset link', 'Offboarding status']);
  });

  it('name the activation link for a pending account', () => {
    expect(actions(render({ ...member, pending: true }, false))).toContain('Activation link');
  });
});
