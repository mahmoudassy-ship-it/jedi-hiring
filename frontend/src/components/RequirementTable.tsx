import { Link } from '@tanstack/react-router'
import type { RequirementList } from '../lib/api'
import { titleCase } from '../lib/format'

type RequirementTableProps = {
  result: RequirementList | null
  loading: boolean
  onPageChange: (page: number) => void
}

function ExternalLinkIcon() {
  return (
    <svg aria-hidden="true" viewBox="0 0 16 16">
      <path d="M9 2.5h4.5V7M13.2 2.8 7.5 8.5" />
      <path d="M7 4H3.5v8.5H12V9" />
    </svg>
  )
}

export function RequirementTable({ result, loading, onPageChange }: RequirementTableProps) {
  if (loading && !result) return <p className="table-state">Loading legal rules…</p>
  if (!result || result.items.length === 0) return <p className="table-state">No rules match these filters.</p>

  const first = (result.page - 1) * result.page_size + 1
  const last = Math.min(result.page * result.page_size, result.total)

  return (
    <section aria-labelledby="requirements-heading" className="requirements-region">
      <h2 className="visually-hidden" id="requirements-heading">Legal requirements</h2>
      <div aria-label="Scrollable legal requirements table" className="table-wrap" tabIndex={0}>
        <table className="legal-table">
          <thead>
            <tr>
              <th scope="col">Rule</th>
              <th scope="col">Source</th>
              <th scope="col">Article / location</th>
              <th scope="col">Effect</th>
              <th scope="col">Status</th>
              <th scope="col">Applicable hiring stages</th>
              <th scope="col">Summary & official source</th>
            </tr>
          </thead>
          <tbody>
            {result.items.map((requirement) => (
              <tr key={requirement.slug}>
                <td>
                  <Link className="rule-link" params={{ slug: requirement.slug }} to="/rules/$slug">
                    {requirement.title}
                  </Link>
                </td>
                <td>
                  <span className="source-name">{requirement.instrument_short_title}</span>
                  <span className="secondary-text">{requirement.jurisdiction_name}</span>
                </td>
                <td>{requirement.source_locator}</td>
                <td><span className={`effect effect-${requirement.legal_effect}`}>{titleCase(requirement.legal_effect)}</span></td>
                <td>
                  <span className={`status status-${requirement.status}`}>{titleCase(requirement.status)}</span>
                  {requirement.effective_from ? <span className="secondary-text">{requirement.effective_from}</span> : null}
                </td>
                <td>{requirement.hiring_stages.join(', ')}</td>
                <td>
                  <p className="rule-summary">{requirement.plain_summary}</p>
                  <a className="official-link" href={requirement.official_url} rel="noreferrer" target="_blank">
                    EUR-Lex: {requirement.instrument_short_title}
                    <ExternalLinkIcon />
                  </a>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <footer className="table-footer">
        <p>{first}–{last} of {result.total} rules</p>
        <nav aria-label="Requirements pagination" className="pagination">
          <button disabled={result.page <= 1} onClick={() => onPageChange(result.page - 1)} type="button">
            Previous
          </button>
          <span aria-current="page">Page {result.page} of {result.total_pages}</span>
          <button disabled={result.page >= result.total_pages} onClick={() => onPageChange(result.page + 1)} type="button">
            Next
          </button>
        </nav>
      </footer>
    </section>
  )
}
