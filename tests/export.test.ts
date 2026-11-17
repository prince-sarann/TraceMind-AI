import { describe, expect, it } from 'vitest';
import { csvEscape } from '../src/lib/api';

describe('CSV export escaping', () => {
  it('neutralizes spreadsheet formula initiators', () => {
    expect(csvEscape('=1+1')).toBe("'=1+1");
    expect(csvEscape('  =HYPERLINK("https://example.invalid")')).toBe("'  =HYPERLINK(\"https://example.invalid\")");
    expect(csvEscape('+SUM(A1:A2)')).toBe("'+SUM(A1:A2)");
    expect(csvEscape('-10')).toBe("'-10");
  });

  it('quotes commas, quotes, and line breaks using CSV escaping rules', () => {
    expect(csvEscape('alpha,beta')).toBe('"alpha,beta"');
    expect(csvEscape('say "hello"')).toBe('"say ""hello"""');
    expect(csvEscape('first line\nsecond line')).toBe('"first line\nsecond line"');
    expect(csvEscape('plain text')).toBe('plain text');
  });
});
