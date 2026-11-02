/**
 * A list of long values (redirect URIs, URLs) shown in one table cell: the first value,
 * truncated by CSS, a "+N more" note, and every value for the cell's tooltip. The full
 * list stays in the record's detail view.
 */
export function listCell(values: readonly string[]): { first: string; more: string; title: string } {
  const shown = values.filter((v) => v.trim() !== '');
  return {
    first: shown[0] ?? '',
    more: shown.length > 1 ? `+${shown.length - 1} more` : '',
    title: shown.join('\n'),
  };
}
