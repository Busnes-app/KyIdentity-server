import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { GroupName, GroupRowActions } from './AdminGroups';
import type { DirectoryGroup } from '../types';

const group: DirectoryGroup = { id: 'g1', name: 'Family', description: '', memberCount: 2, member: false, createdAt: '', updatedAt: '' };
const none = () => {};
const actions = (html: string) => [...html.matchAll(/class="row-action[^"]*"[^>]*>(?:<svg[\s\S]*?<\/svg>)?([^<]+)/g)].map((m) => m[1]);

describe('group name', () => {
  it('is a button that opens Manage (the members) on the groups list', () => {
    expect(renderToStaticMarkup(<GroupName group={group} busy={false} onManage={none} />))
      .toBe('<button type="button" class="cell-link"><span class="sr-only">Manage </span>Family<span class="sr-only"> members</span></button>');
  });
  it('stays text where the list offers no Manage (one user\'s memberships)', () => {
    expect(renderToStaticMarkup(<GroupName group={group} busy={false} />)).toBe('Family');
  });
});

describe('group row actions', () => {
  const html = renderToStaticMarkup(<GroupRowActions group={group} busy={false} onMembers={none} onEdit={none} onPolicy={none} onDelete={none} />);
  it('open from a quiet ⋯ button, with no outlined Manage button', () => {
    expect(html).toMatch(/<button type="button" class="icon-btn sm" popover[Tt]arget="[^"]+" aria-label="More actions for Family"><svg[^>]*aria-hidden="true"/);
    expect(html).not.toContain('secondary-btn');
  });
  it('lead with Manage and keep every other action, delete last', () => {
    expect(actions(html)).toEqual(['Manage', 'Edit group', 'MFA policy', 'Delete group']);
  });
});
