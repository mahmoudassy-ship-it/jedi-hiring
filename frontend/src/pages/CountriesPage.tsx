import type { Jurisdiction } from '../lib/api'
import { useApi } from '../lib/api'
import { titleCase } from '../lib/format'

export function CountriesPage() {
  const jurisdictions = useApi<Jurisdiction[]>('/api/jurisdictions')

  return (
    <main className="app-page secondary-page">
      <header className="page-heading">
        <h1>Jurisdictions</h1>
        <p>The EU core is ready. National cards will be added as explicit, dated overlays rather than folded invisibly into EU summaries.</p>
      </header>

      {jurisdictions.loading ? <p>Loading jurisdictions…</p> : null}
      {jurisdictions.error ? <p role="alert">The jurisdiction register could not be loaded.</p> : null}
      {jurisdictions.data ? (
        <div className="jurisdiction-list">
          {jurisdictions.data.map((jurisdiction) => (
            <article key={jurisdiction.code}>
              <div>
                <p>{jurisdiction.code} · {titleCase(jurisdiction.level)}</p>
                <h2>{jurisdiction.name}</h2>
                <p>{jurisdiction.notes}</p>
              </div>
              <dl>
                <div><dt>Official instruments</dt><dd>{jurisdiction.instrument_count}</dd></div>
                <div><dt>National overlays</dt><dd>{jurisdiction.overlay_count}</dd></div>
              </dl>
            </article>
          ))}
        </div>
      ) : null}
    </main>
  )
}
