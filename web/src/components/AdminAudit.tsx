import React, { useEffect, useState, useRef, useCallback } from 'react';
import { AuditEvent } from '../types';
import { apiJson } from '../api';
import { parseAuditPage } from '../parsers';
import { instantFromLocal, localZone } from '../instant';
import {
  RefreshCw,
  CheckCircle,
  AlertTriangle,
  XCircle,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  ChevronDown,
  ChevronUp,
  Pause,
  Play,
} from 'lucide-react';

export const AdminAudit: React.FC = () => {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [loading, setLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [refreshInterval, setRefreshInterval] = useState(10); // seconds
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [filter, setFilter] = useState({ actor: '', target: '', action: '', outcome: '', from: '', to: '' });
  const filterQuery = () => {
    const q = new URLSearchParams();
    if (filter.actor.trim()) q.set('actor', filter.actor.trim());
    if (filter.target.trim()) q.set('target', filter.target.trim());
    if (filter.action.trim()) q.set('action', filter.action.trim());
    if (filter.outcome) q.set('outcome', filter.outcome);
    const from = instantFromLocal(filter.from); if (from) q.set('from', from);
    const to = instantFromLocal(filter.to); if (to) q.set('to', to);
    return q.toString();
  };

  const scrollRef = useRef<HTMLDivElement>(null);
  const timerRef = useRef<number | null>(null);

  const fetchEvents = useCallback(
    async (targetPage = page, targetLimit = pageSize, isBackground = false) => {
      if (isBackground) {
        setIsRefreshing(true);
      } else {
        setLoading(true);
      }

      try {
        const page = await apiJson(
          `/api/admin/audit-events?page=${targetPage}&limit=${targetLimit}&${filterQuery()}`,
          parseAuditPage
        );
        setEvents(page.events);
        setTotal(page.total);
      } catch {
        // A failed background poll leaves the current page on screen.
      } finally {
        setLoading(false);
        setIsRefreshing(false);
      }
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [page, pageSize, filter]
  );

  // Initial load or page/size change
  useEffect(() => {
    fetchEvents(page, pageSize, false);
  }, [page, pageSize, fetchEvents]);

  // Auto-refresh interval
  useEffect(() => {
    if (timerRef.current) {
      clearInterval(timerRef.current);
      timerRef.current = null;
    }

    if (autoRefresh && refreshInterval > 0) {
      timerRef.current = window.setInterval(() => {
        if (document.visibilityState === 'visible') {
          fetchEvents(page, pageSize, true);
        }
      }, refreshInterval * 1000);
    }

    return () => {
      if (timerRef.current) {
        clearInterval(timerRef.current);
      }
    };
  }, [autoRefresh, refreshInterval, page, pageSize, fetchEvents]);

  // Catch up immediately on tab resume
  useEffect(() => {
    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible' && autoRefresh) {
        fetchEvents(page, pageSize, true);
      }
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);
    return () => {
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, [autoRefresh, page, pageSize, fetchEvents]);

  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  const handlePageChange = (newPage: number) => {
    if (newPage >= 1 && newPage <= totalPages && newPage !== page) {
      setPage(newPage);
      if (scrollRef.current) {
        scrollRef.current.scrollTop = 0;
      }
    }
  };

  const handlePageSizeChange = (newSize: number) => {
    setPageSize(newSize);
    setPage(1);
    if (scrollRef.current) {
      scrollRef.current.scrollTop = 0;
    }
  };

  const toggleExpand = (id: string) => {
    setExpandedId((prev) => (prev === id ? null : id));
  };

  // Compute visible page numbers
  const getPageNumbers = () => {
    const pages: (number | string)[] = [];
    const maxVisible = 5;

    if (totalPages <= maxVisible + 2) {
      for (let i = 1; i <= totalPages; i++) pages.push(i);
    } else {
      pages.push(1);
      const start = Math.max(2, page - 1);
      const end = Math.min(totalPages - 1, page + 1);

      if (start > 2) pages.push('...');
      for (let i = start; i <= end; i++) pages.push(i);
      if (end < totalPages - 1) pages.push('...');
      pages.push(totalPages);
    }
    return pages;
  };

  const startRecord = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const endRecord = Math.min(page * pageSize, total);

  return (
    <div className="admin-page">
      <div className="page-header">
        <div>
          <h1 className="page-title">Audit log</h1>
        </div>
        <div className="audit-actions-group">
          <button
            className={`secondary-btn sm ${autoRefresh ? 'active' : ''}`}
            onClick={() => setAutoRefresh(!autoRefresh)}
            title={autoRefresh ? 'Pause auto-refresh' : 'Enable auto-refresh'}
          >
            <span className={`live-indicator-dot ${autoRefresh ? 'active' : ''}`} />
            {autoRefresh ? (
              <>
                <Pause size={13} />
                <span>Auto ({refreshInterval}s)</span>
              </>
            ) : (
              <>
                <Play size={13} />
                <span>Auto-Refresh Off</span>
              </>
            )}
          </button>

          <button
            className="secondary-btn sm"
            onClick={() => fetchEvents(page, pageSize, false)}
            disabled={loading || isRefreshing}
            title="Refresh now"
          >
            <RefreshCw className={loading || isRefreshing ? 'spin' : ''} size={14} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      <section className="settings-section">
        <div className="section-header"><div className="section-title-wrap"><h2>Filter</h2></div>
          <div className="action-buttons-wrap">
            <a className="secondary-btn sm" href={`/api/admin/audit-events/export?format=csv&${filterQuery()}`} download>Export CSV</a>
            <a className="secondary-btn sm" href={`/api/admin/audit-events/export?format=jsonl&${filterQuery()}`} download>Export JSONL</a>
          </div></div>
        <p className="text-muted text-sm">Exports carry the same filter as this page, at most 50,000 rows, with credential-shaped details redacted; each export is itself audited.</p>
        <div className="form-row">
          <div className="form-group flex-1"><label className="form-label" htmlFor="audit-actor">Actor (id or username)</label><input id="audit-actor" className="form-input" maxLength={200} value={filter.actor} onChange={e => { setFilter({ ...filter, actor: e.target.value }); setPage(1); }} /></div>
          <div className="form-group flex-1"><label className="form-label" htmlFor="audit-target">Target id</label><input id="audit-target" className="form-input" maxLength={200} value={filter.target} onChange={e => { setFilter({ ...filter, target: e.target.value }); setPage(1); }} /></div>
          <div className="form-group flex-1"><label className="form-label" htmlFor="audit-action">Action (prefix, e.g. oauth.)</label><input id="audit-action" className="form-input font-mono" maxLength={200} value={filter.action} onChange={e => { setFilter({ ...filter, action: e.target.value }); setPage(1); }} /></div>
          <div className="form-group"><label className="form-label" htmlFor="audit-outcome">Outcome</label><select id="audit-outcome" className="form-select" value={filter.outcome} onChange={e => { setFilter({ ...filter, outcome: e.target.value }); setPage(1); }}><option value="">Any</option><option value="success">Success</option><option value="failure">Failure</option><option value="denied">Denied</option></select></div>
        </div>
        <div className="form-row">
          <div className="form-group flex-1"><label className="form-label" htmlFor="audit-from">From ({localZone()})</label><input id="audit-from" type="datetime-local" className="form-input" value={filter.from} onChange={e => { setFilter({ ...filter, from: e.target.value }); setPage(1); }} /></div>
          <div className="form-group flex-1"><label className="form-label" htmlFor="audit-to">To ({localZone()})</label><input id="audit-to" type="datetime-local" className="form-input" value={filter.to} onChange={e => { setFilter({ ...filter, to: e.target.value }); setPage(1); }} /></div>
        </div>
      </section>

      <div className="audit-container">
        {/* Controls header bar */}
        <div className="audit-controls-bar">
          <div className="pagination-info">
            {total > 0 ? (
              <span>
                Showing <strong className="text-white">{startRecord}</strong>–
                <strong className="text-white">{endRecord}</strong> of{' '}
                <strong className="text-cyan">{total}</strong> events
              </span>
            ) : (
              <span>0 events</span>
            )}
          </div>

          <div className="audit-actions-group">
            <div className="page-size-selector">
              <label htmlFor="audit-page-size">Per page:</label>
              <select
                id="audit-page-size"
                className="page-size-select"
                value={pageSize}
                onChange={(e) => handlePageSizeChange(Number(e.target.value))}
              >
                <option value={10}>10</option>
                <option value={25}>25</option>
                <option value={50}>50</option>
                <option value={100}>100</option>
              </select>
            </div>

            <div className="page-size-selector">
              <label htmlFor="audit-cadence">Cadence:</label>
              <select
                id="audit-cadence"
                className="page-size-select"
                value={refreshInterval}
                disabled={!autoRefresh}
                onChange={(e) => setRefreshInterval(Number(e.target.value))}
              >
                <option value={5}>5s</option>
                <option value={10}>10s</option>
                <option value={30}>30s</option>
                <option value={60}>60s</option>
              </select>
            </div>
          </div>
        </div>

        {/* Scrollable Table Window */}
        <div className="audit-scroll-window" ref={scrollRef}>
          <table className="admin-table">
            <thead>
              <tr>
                <th style={{ width: '40px' }}></th>
                <th>Timestamp</th>
                <th>Action</th>
                <th>Actor</th>
                <th>Target</th>
                <th>IP Address</th>
                <th>Outcome</th>
              </tr>
            </thead>
            <tbody>
              {loading && events.length === 0 ? (
                <tr>
                  <td colSpan={7} className="text-center py-5 text-muted">
                    <RefreshCw className="spin icon-cyan" size={20} style={{ margin: '0 auto 0.5rem' }} />
                    <div>Loading audit trail...</div>
                  </td>
                </tr>
              ) : events.length === 0 ? (
                <tr>
                  <td colSpan={7} className="text-center py-5 text-muted">
                    No audit events recorded yet.
                  </td>
                </tr>
              ) : (
                events.map((e) => {
                  const isExpanded = expandedId === e.id;
                  let parsedDetails: unknown = null;
                  if (e.detailsJson) {
                    try {
                      parsedDetails = JSON.parse(e.detailsJson);
                    } catch {
                      parsedDetails = e.detailsJson;
                    }
                  }

                  return (
                    <React.Fragment key={e.id}>
                      <tr
                        className={`audit-row ${isExpanded ? 'expanded' : ''}`}
                        onClick={() => toggleExpand(e.id)}
                        title="Click to view details"
                      >
                        <td className="text-center text-muted" style={{ padding: '0.5rem' }}>
                          {isExpanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                        </td>
                        <td className="font-mono text-sm text-muted" style={{ whiteSpace: 'nowrap' }}>
                          {new Date(e.createdAt).toLocaleString()}
                        </td>
                        <td className="font-mono font-bold text-cyan">{e.action}</td>
                        <td>{e.actorUsername || e.actorId || 'system'}</td>
                        <td className="text-muted text-sm">
                          {e.targetType ? `${e.targetType}:${e.targetId}` : '—'}
                        </td>
                        <td className="font-mono text-sm text-muted">{e.ipAddress}</td>
                        <td>
                          {e.outcome === 'success' && (
                            <span className="status-badge active">
                              <CheckCircle size={12} /> Success
                            </span>
                          )}
                          {e.outcome === 'failure' && (
                            <span className="status-badge warn">
                              <AlertTriangle size={12} /> Failure
                            </span>
                          )}
                          {e.outcome === 'denied' && (
                            <span className="status-badge disabled">
                              <XCircle size={12} /> Denied
                            </span>
                          )}
                        </td>
                      </tr>

                      {/* Expandable row detail */}
                      {isExpanded && (
                        <tr className="audit-details-row">
                          <td colSpan={7}>
                            <div className="audit-details-card">
                              <div className="audit-details-grid">
                                <div className="audit-detail-item">
                                  <span className="audit-detail-label">Event ID</span>
                                  <span className="audit-detail-value">{e.id}</span>
                                </div>
                                <div className="audit-detail-item">
                                  <span className="audit-detail-label">Actor ID</span>
                                  <span className="audit-detail-value">{e.actorId || '—'}</span>
                                </div>
                                <div className="audit-detail-item">
                                  <span className="audit-detail-label">Target ID</span>
                                  <span className="audit-detail-value">{e.targetId || '—'}</span>
                                </div>
                                <div className="audit-detail-item">
                                  <span className="audit-detail-label">User Agent</span>
                                  <span className="audit-detail-value text-muted" style={{ fontSize: '0.78rem' }}>
                                    {e.userAgent || '—'}
                                  </span>
                                </div>
                              </div>

                              {parsedDetails !== null && parsedDetails !== undefined && (
                                <div className="audit-detail-item">
                                  <span className="audit-detail-label">Event Payload / Details</span>
                                  <pre className="audit-json-box">
                                    {typeof parsedDetails === 'object'
                                      ? JSON.stringify(parsedDetails, null, 2)
                                      : String(parsedDetails)}
                                  </pre>
                                </div>
                              )}
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination navigation footer */}
        <div className="pagination-bar">
          <div className="pagination-info">
            Page <strong className="text-white">{page}</strong> of{' '}
            <strong className="text-white">{totalPages}</strong>
          </div>

          <div className="pagination-nav">
            <button
              className="pagination-page-btn"
              onClick={() => handlePageChange(1)}
              disabled={page <= 1 || loading}
              title="First page"
            >
              <ChevronsLeft size={14} />
            </button>
            <button
              className="pagination-page-btn"
              onClick={() => handlePageChange(page - 1)}
              disabled={page <= 1 || loading}
              title="Previous page"
            >
              <ChevronLeft size={14} />
            </button>

            {getPageNumbers().map((pageNum, idx) =>
              pageNum === '...' ? (
                <span key={`ellipsis-${idx}`} className="pagination-info" style={{ padding: '0 0.25rem' }}>
                  …
                </span>
              ) : (
                <button
                  key={`page-${pageNum}`}
                  className={`pagination-page-btn ${page === pageNum ? 'active' : ''}`}
                  onClick={() => handlePageChange(pageNum as number)}
                  disabled={loading}
                >
                  {pageNum}
                </button>
              )
            )}

            <button
              className="pagination-page-btn"
              onClick={() => handlePageChange(page + 1)}
              disabled={page >= totalPages || loading}
              title="Next page"
            >
              <ChevronRight size={14} />
            </button>
            <button
              className="pagination-page-btn"
              onClick={() => handlePageChange(totalPages)}
              disabled={page >= totalPages || loading}
              title="Last page"
            >
              <ChevronsRight size={14} />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
