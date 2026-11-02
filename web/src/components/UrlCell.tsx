import React from 'react';
import { listCell } from '../listCell';

/** One or more URLs in a table cell: the first on one truncated line, the rest counted; the tooltip has them all. */
export const UrlCell: React.FC<{ values: readonly string[] }> = ({ values }) => {
  const { first, more, title } = listCell(values);
  return <span className="cell-stack">
    <span className="cell-truncate font-mono" title={title}>{first || '—'}</span>
    {more && <span className="cell-meta">{more}</span>}
  </span>;
};
