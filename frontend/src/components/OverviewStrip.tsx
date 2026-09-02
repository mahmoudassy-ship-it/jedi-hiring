import type { Overview } from '../lib/api'

type OverviewStripProps = {
  overview: Overview | null
}

function RulesIcon() {
  return (
    <svg aria-hidden="true" className="metric-icon" viewBox="0 0 24 24">
      <path d="M7 3.5h7l4 4V20.5H7z" />
      <path d="M14 3.5v4h4M10 12h5M10 16h5" />
    </svg>
  )
}

function SourcesIcon() {
  return (
    <svg aria-hidden="true" className="metric-icon" viewBox="0 0 24 24">
      <path d="M3.5 5.5c3-1.7 5.7-1.5 8.5.5v14c-2.8-2-5.5-2.2-8.5-.5zM20.5 5.5c-3-1.7-5.7-1.5-8.5.5v14c2.8-2 5.5-2.2 8.5-.5z" />
    </svg>
  )
}

function JurisdictionsIcon() {
  return (
    <svg aria-hidden="true" className="metric-icon metric-icon-muted" viewBox="0 0 24 24">
      <circle cx="12" cy="12" r="9" />
      <path d="M3.5 12h17M12 3c2.2 2.4 3.3 5.4 3.3 9S14.2 18.6 12 21M12 3c-2.2 2.4-3.3 5.4-3.3 9S9.8 18.6 12 21" />
    </svg>
  )
}

export function OverviewStrip({ overview }: OverviewStripProps) {
  const metrics = [
    { label: 'Rules', value: overview?.requirements, icon: <RulesIcon /> },
    { label: 'Official sources', value: overview?.official_sources, icon: <SourcesIcon /> },
    { label: 'Jurisdictions', value: overview?.jurisdictions, icon: <JurisdictionsIcon /> },
  ]

  return (
    <dl className="overview-strip" aria-label="Dataset overview">
      {metrics.map((metric) => (
        <div className="overview-metric" key={metric.label}>
          {metric.icon}
          <div>
            <dt>{metric.label}</dt>
            <dd>{metric.value ?? '—'}</dd>
          </div>
        </div>
      ))}
    </dl>
  )
}
