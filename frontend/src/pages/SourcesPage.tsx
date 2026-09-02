import type { Instrument } from '../lib/api'
import { useApi } from '../lib/api'
import { formatDate, titleCase } from '../lib/format'

export function SourcesPage() {
  const instruments = useApi<Instrument[]>('/api/instruments')

  return (
    <main className="app-page secondary-page">
      <header className="page-heading">
        <h1>Official sources</h1>
        <p>Each editorial rule stays connected to the official instrument, its legal status, and the date the source was checked.</p>
      </header>

      {instruments.loading ? <p>Loading sources…</p> : null}
      {instruments.error ? <p role="alert">The source register could not be loaded.</p> : null}
      {instruments.data ? (
        <div className="source-list">
          {instruments.data.map((instrument) => (
            <article key={instrument.slug}>
              <div>
                <p>{instrument.citation} · {instrument.jurisdiction_name}</p>
                <h2><a href={instrument.official_url} rel="noreferrer" target="_blank">{instrument.short_title} ↗</a></h2>
                <p>{instrument.title}</p>
              </div>
              <dl>
                <div><dt>Type</dt><dd>{titleCase(instrument.instrument_type)}</dd></div>
                <div><dt>Status</dt><dd>{titleCase(instrument.status)}</dd></div>
                <div><dt>Rules</dt><dd>{instrument.requirement_count}</dd></div>
                <div><dt>Checked</dt><dd>{formatDate(instrument.last_verified_on)}</dd></div>
              </dl>
            </article>
          ))}
        </div>
      ) : null}
    </main>
  )
}
