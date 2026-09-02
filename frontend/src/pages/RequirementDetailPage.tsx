import { Link } from '@tanstack/react-router'
import type { Requirement } from '../lib/api'
import { useApi } from '../lib/api'
import { formatDate, titleCase } from '../lib/format'

type RequirementDetailPageProps = {
  slug: string
}

export function RequirementDetailPage({ slug }: RequirementDetailPageProps) {
  const requirement = useApi<Requirement>(`/api/requirements/${encodeURIComponent(slug)}`)

  if (requirement.loading) return <main className="app-page detail-page"><p>Loading rule…</p></main>
  if (requirement.error || !requirement.data) {
    return <main className="app-page detail-page"><p role="alert">This legal rule could not be loaded.</p></main>
  }

  const data = requirement.data

  return (
    <main className="app-page detail-page">
      <Link className="back-link" to="/">← Legal map</Link>
      <header className="detail-heading">
        <p>{data.instrument_short_title} · {data.source_locator}</p>
        <h1>{data.title}</h1>
        <div className="detail-labels">
          <span className={`effect effect-${data.legal_effect}`}>{titleCase(data.legal_effect)}</span>
          <span className={`status status-${data.status}`}>{titleCase(data.status)}</span>
        </div>
        <p className="detail-summary">{data.plain_summary}</p>
        <a className="official-source-button" href={data.official_url} rel="noreferrer" target="_blank">
          Open official source ↗
        </a>
      </header>

      <div className="detail-grid">
        <section>
          <h2>What to do</h2>
          <p>{data.compliance_action}</p>
        </section>
        <section>
          <h2>Escalate when</h2>
          <p>{data.escalation_trigger || 'No escalation trigger recorded.'}</p>
        </section>
        <section>
          <h2>Application timing</h2>
          <p>{data.effective_note || 'No additional timing note recorded.'}</p>
          <dl className="metadata-list">
            <div><dt>Effective from</dt><dd>{formatDate(data.effective_from)}</dd></div>
            <div><dt>Source checked</dt><dd>{formatDate(data.source_last_verified_on)}</dd></div>
            <div><dt>Research reviewed</dt><dd>{formatDate(data.last_reviewed_on)}</dd></div>
          </dl>
        </section>
        <section>
          <h2>Scope</h2>
          <dl className="metadata-list">
            <div><dt>Hiring stages</dt><dd>{data.hiring_stages.join(', ')}</dd></div>
            <div><dt>Legal lenses</dt><dd>{data.legal_lenses.join(', ')}</dd></div>
            <div><dt>Actors</dt><dd>{data.actors.join(', ')}</dd></div>
            <div><dt>Validation</dt><dd>{titleCase(data.review_status)}</dd></div>
          </dl>
        </section>
      </div>

      <section className="relations-section">
        <h2>Connected rules</h2>
        {data.relations && data.relations.length > 0 ? (
          <ul>
            {data.relations.map((relation) => (
              <li key={`${relation.direction}-${relation.relation_type}-${relation.slug}`}>
                <Link params={{ slug: relation.slug }} to="/rules/$slug">{relation.title}</Link>
                <span>{titleCase(relation.relation_type)}</span>
                {relation.notes ? <p>{relation.notes}</p> : null}
              </li>
            ))}
          </ul>
        ) : <p>No cross-links recorded yet.</p>}
      </section>
    </main>
  )
}
