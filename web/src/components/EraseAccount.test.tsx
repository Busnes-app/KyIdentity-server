import { describe, expect, it } from 'vitest';
import { eraseSummary, parseEraseScope } from './EraseAccount';
import { parseEnrollmentStatus } from '../parsers';

describe('Delete everything', () => {
  it('parses the options answer and refuses anything else', () => {
    expect(parseEraseScope({ holder: true, otherMembers: 2 })).toEqual({ holder: true, otherMembers: 2 });
    for (const bad of [null, {}, { holder: 'yes', otherMembers: 0 }, { holder: false }]) {
      expect(() => parseEraseScope(bad)).toThrow();
    }
  });

  it('says what each click deletes', () => {
    expect(eraseSummary({ holder: false, otherMembers: 0 })).toMatch(/^Deletes your account .*household keeps theirs/);
    expect(eraseSummary({ holder: true, otherMembers: 0 })).toMatch(/straight away/);
    expect(eraseSummary({ holder: true, otherMembers: 1 })).toMatch(/1 other person can export .* 7 days/);
    expect(eraseSummary({ holder: true, otherMembers: 3 })).toMatch(/3 other people/);
  });

  it('reads exportOnly only when the server says true', () => {
    const base = { required: false, allowedMethods: ['totp'], deadline: 0, enrolled: false, restricted: false };
    expect(parseEnrollmentStatus(base)).toEqual(base);
    expect(parseEnrollmentStatus({ ...base, exportOnly: true })).toEqual({ ...base, exportOnly: true });
    expect(parseEnrollmentStatus({ ...base, exportOnly: 'yes' })).toEqual(base);
  });
});
