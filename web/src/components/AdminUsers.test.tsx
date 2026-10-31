import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { AccountName, UserRowActions, filterUsers } from './AdminUsers';
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

  it('open from a quiet ⋯ button named for the account, never a Manage button', () => {
    const html = render(member, false);
    expect(html).toMatch(/<button type="button" class="icon-btn sm" popover[Tt]arget="[^"]+" aria-label="More actions for member"><svg[^>]*aria-hidden="true"/);
    expect(html).not.toContain('Manage<');
  });

  it('name the activation link for a pending account', () => {
    expect(actions(render({ ...member, pending: true }, false))).toContain('Activation link');
  });
});

describe('user list filter', () => {
  const list: User[] = [{ ...admin, status: 'active' }, { ...member, status: 'active' }, { ...member, id: 'p1', username: 'priya', displayName: 'Priya Shah', email: 'p@x.test', pending: true },
    { ...member, id: 'd1', username: 'gone', displayName: '', email: 'gone@x.test', status: 'disabled' }];
  const ids = (f: Parameters<typeof filterUsers>[1]) => filterUsers(list, f).map(u => u.id);
  const all = { query: '', role: 'all', status: 'all' } as const;

  it('keeps every account with no filter', () => expect(ids(all)).toEqual(['a1', 'u1', 'p1', 'd1']));
  it('matches account, display name or email, ignoring case and spaces', () => {
    expect(ids({ ...all, query: ' SHAH ' })).toEqual(['p1']);
    expect(ids({ ...all, query: 'gone@' })).toEqual(['d1']);
    expect(ids({ ...all, query: 'admin' })).toEqual(['a1']);
  });
  it('filters by role and by status, pending before active', () => {
    expect(ids({ ...all, role: 'admin' })).toEqual(['a1']);
    expect(ids({ ...all, status: 'pending' })).toEqual(['p1']);
    expect(ids({ ...all, status: 'active' })).toEqual(['a1', 'u1']);
    expect(ids({ ...all, status: 'disabled' })).toEqual(['d1']);
  });
});

describe('account name', () => {
  it('is a button that edits the account for a full administrator', () => {
    const html = renderToStaticMarkup(<AccountName u={member} busy={false} onEdit={none} />);
    expect(html).toBe('<button type="button" class="cell-link"><span class="sr-only">Edit </span>Member</button>');
  });
  it('falls back to the username and stays text for a delegate', () => {
    expect(renderToStaticMarkup(<AccountName u={{ ...member, displayName: '' }} busy={false} />)).toBe('member');
  });
});
