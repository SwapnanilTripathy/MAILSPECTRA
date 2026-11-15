import React from 'react';

export function TableLoadingSkeleton({ rows = 5, columns = 6 }) {
  return (
    <div
      className="mailspectra-table-skeleton"
      style={{ '--skeleton-columns': columns }}
      role="status"
      aria-label="Loading table data"
    >
      <span className="sr-only">Loading table data</span>
      <div className="mailspectra-skeleton-row is-heading" aria-hidden="true">
        {Array.from({ length: columns }, (_, index) => (
          <span className="mailspectra-skeleton-block" key={index} />
        ))}
      </div>
      {Array.from({ length: rows }, (_, row) => (
        <div className="mailspectra-skeleton-row" aria-hidden="true" key={row}>
          {Array.from({ length: columns }, (_, column) => (
            <span
              className="mailspectra-skeleton-block"
              key={column}
              style={{ width: column === 1 ? '88%' : column === columns - 1 ? '54%' : '72%' }}
            />
          ))}
        </div>
      ))}
    </div>
  );
}

export function ChartLoadingSkeleton({ variant = 'bars', rows = 4 }) {
  return (
    <div className={`mailspectra-chart-skeleton ${variant === 'donut' ? 'is-donut' : 'is-bars'}`} role="status" aria-label="Loading chart data">
      <span className="sr-only">Loading chart data</span>
      {variant === 'donut' ? (
        <div className="mailspectra-skeleton-donut mailspectra-skeleton-block" aria-hidden="true" />
      ) : (
        <div className="mailspectra-skeleton-bars" aria-hidden="true">
          {Array.from({ length: rows }, (_, index) => (
            <span className="mailspectra-skeleton-block" key={index} style={{ width: `${88 - index * 13}%` }} />
          ))}
        </div>
      )}
      <div className="mailspectra-skeleton-legend" aria-hidden="true">
        {Array.from({ length: rows }, (_, index) => (
          <div key={index}>
            <span className="mailspectra-skeleton-block" />
            <span className="mailspectra-skeleton-block" />
          </div>
        ))}
      </div>
    </div>
  );
}

export function CardListLoadingSkeleton({ rows = 3 }) {
  return (
    <div className="mailspectra-card-skeleton-list" role="status" aria-label="Loading campaign data">
      <span className="sr-only">Loading campaign data</span>
      {Array.from({ length: rows }, (_, index) => (
        <div className="mailspectra-card-skeleton" aria-hidden="true" key={index}>
          <span className="mailspectra-skeleton-block" />
          <span className="mailspectra-skeleton-block" />
        </div>
      ))}
    </div>
  );
}
