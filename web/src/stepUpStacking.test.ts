import { readdirSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

/**
 * The step-up prompt is opened from inside a feature modal that stays mounted — Register
 * Client asks for a grant without closing its own form. If the prompt does not stack above
 * that modal it is buried: invisible, unclickable, and the grant promise never settles.
 * Modal.tsx opens with showModal(), whose top layer stacks the later dialog on top whatever
 * the z-index, so every modal has to go through it.
 */
const components = new URL('./components/', import.meta.url);
const source = (name: string) => readFileSync(new URL(name, components), 'utf8');

const unmigrated = new Set(['Modal.tsx']);

describe('modal stacking', () => {
  it('opens modals in the top layer', () => {
    expect(source('Modal.tsx')).toContain('.showModal()');
  });

  it('renders the step-up prompt through Modal', () => {
    expect(source('StepUpPrompt.tsx')).toContain('<Modal ');
  });

  it('leaves no hand-rolled backdrop outside Modal', () => {
    const offenders = readdirSync(components)
      .filter(name => name.endsWith('.tsx') && !unmigrated.has(name))
      .filter(name => source(name).includes('modal-backdrop'));
    expect(offenders).toEqual([]);
  });
});
