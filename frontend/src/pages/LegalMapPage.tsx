import { useDeferredValue, useMemo, useState } from 'react'
import { OverviewStrip } from '../components/OverviewStrip'
import { RequirementTable } from '../components/RequirementTable'
import type { Overview, RequirementList, Taxonomies } from '../lib/api'
import { useApi } from '../lib/api'
import { titleCase } from '../lib/format'

function SearchIcon() {
  return (
    <svg aria-hidden="true" viewBox="0 0 24 24">
      <circle cx="10.5" cy="10.5" r="6.5" />
      <path d="m15.5 15.5 5 5" />
    </svg>
  )
}

export function LegalMapPage() {
  const [search, setSearch] = useState('')
  const [stage, setStage] = useState('')
  const [lens, setLens] = useState('')
  const [effect, setEffect] = useState('')
  const [status, setStatus] = useState('')
  const [page, setPage] = useState(1)
  const deferredSearch = useDeferredValue(search)
  const overview = useApi<Overview>('/api/overview')
  const taxonomies = useApi<Taxonomies>('/api/taxonomies')

  const requirementsUrl = useMemo(() => {
    const parameters = new URLSearchParams({ page: String(page), page_size: '25' })
    if (deferredSearch.trim()) parameters.set('q', deferredSearch.trim())
    if (stage) parameters.set('stage', stage)
    if (lens) parameters.set('lens', lens)
    if (effect) parameters.set('effect', effect)
    if (status) parameters.set('status', status)
    return `/api/requirements?${parameters}`
  }, [deferredSearch, effect, lens, page, stage, status])

  const requirements = useApi<RequirementList>(requirementsUrl)
  const hasFilters = Boolean(search || stage || lens || effect || status)

  function resetPageAnd(update: () => void) {
    setPage(1)
    update()
  }

  function clearFilters() {
    setSearch('')
    setStage('')
    setLens('')
    setEffect('')
    setStatus('')
    setPage(1)
  }

  return (
    <main className="app-page legal-map-page">
      <header className="page-heading">
        <h1>Legal map</h1>
        <p>Rules are organized by hiring stage and legal lens to help you navigate inclusive hiring obligations across Europe.</p>
      </header>

      <section aria-label="Filter legal rules" className="filters">
        <label className="search-field">
          <span className="visually-hidden">Search rules</span>
          <SearchIcon />
          <input
            onChange={(event) => resetPageAnd(() => setSearch(event.target.value))}
            placeholder="Search rules"
            type="search"
            value={search}
          />
        </label>

        <div className="filter-grid">
          <label>
            <span>Hiring stage</span>
            <select onChange={(event) => resetPageAnd(() => setStage(event.target.value))} value={stage}>
              <option value="">All stages</option>
              {taxonomies.data?.hiring_stages.map((option) => (
                <option key={option.slug} value={option.slug}>{option.name}</option>
              ))}
            </select>
          </label>
          <label>
            <span>Legal lens</span>
            <select onChange={(event) => resetPageAnd(() => setLens(event.target.value))} value={lens}>
              <option value="">All lenses</option>
              {taxonomies.data?.legal_lenses.map((option) => (
                <option key={option.slug} value={option.slug}>{option.name}</option>
              ))}
            </select>
          </label>
          <label>
            <span>Legal effect</span>
            <select onChange={(event) => resetPageAnd(() => setEffect(event.target.value))} value={effect}>
              <option value="">All effects</option>
              {taxonomies.data?.legal_effects.map((option) => (
                <option key={option.slug} value={option.slug}>{titleCase(option.slug)}</option>
              ))}
            </select>
          </label>
          <label>
            <span>Status</span>
            <select onChange={(event) => resetPageAnd(() => setStatus(event.target.value))} value={status}>
              <option value="">All statuses</option>
              {taxonomies.data?.statuses.map((option) => (
                <option key={option.slug} value={option.slug}>{titleCase(option.slug)}</option>
              ))}
            </select>
          </label>
          <button className="clear-filters" disabled={!hasFilters} onClick={clearFilters} type="button">Clear filters</button>
        </div>
      </section>

      <OverviewStrip overview={overview.data} />

      {overview.error || taxonomies.error || requirements.error
        ? <p className="error-message" role="alert">The legal atlas could not be loaded. Check that the API is running.</p>
        : <RequirementTable loading={requirements.loading} onPageChange={setPage} result={requirements.data} />}
    </main>
  )
}
