import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { PasswordChangeRequired } from './PasswordChangeRequired';
import type { User } from '../types';

const user: User = { id: 'u1', username: 'admin', displayName: 'Administrator', email: 'admin@x.test', role: 'admin', passwordChangeRequired: true };

describe('forced password change screen', () => {
  const html = renderToStaticMarkup(<PasswordChangeRequired user={user} onChanged={() => {}} onLogout={() => {}} />);

  it('asks for the given password and a repeated new one under the server policy', () => {
    expect(html).toContain('Choose a new password');
    expect(html).toContain('Current or temporary password');
    expect(html).toContain('Repeat new password');
    expect(html).toContain('12 to 1024 characters');
    expect(html.match(/minLength="12"/g)).toHaveLength(2);
  });

  it('offers nothing but the change, a factor replacement and sign-out', () => {
    expect(html).toContain('Sign out');
    expect(html).not.toContain('side-nav');
  });
});
