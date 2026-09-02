import { useEffect, useState } from 'react'

export type Overview = {
  requirements: number
  official_sources: number
  jurisdictions: number
  last_verified_on: string
}

export type TaxonomyOption = {
  slug: string
  name?: string
  count?: number
}

export type Taxonomies = {
  hiring_stages: TaxonomyOption[]
  legal_lenses: TaxonomyOption[]
  legal_effects: TaxonomyOption[]
  statuses: TaxonomyOption[]
}

export type RequirementRelation = {
  slug: string
  title: string
  relation_type: string
  notes: string | null
  direction: 'incoming' | 'outgoing'
}

export type Requirement = {
  id: number
  slug: string
  title: string
  plain_summary: string
  source_locator: string
  legal_effect: string
  status: string
  effective_from: string | null
  effective_note: string | null
  compliance_action: string
  escalation_trigger: string | null
  review_status: string
  is_generated: boolean
  last_reviewed_on: string
  instrument_slug: string
  instrument_short_title: string
  instrument_title: string
  citation: string
  instrument_type: string
  official_url: string
  source_last_verified_on: string
  jurisdiction_code: string
  jurisdiction_name: string
  hiring_stages: string[]
  legal_lenses: string[]
  actors: string[]
  relations?: RequirementRelation[]
}

export type RequirementList = {
  items: Requirement[]
  page: number
  page_size: number
  total: number
  total_pages: number
}

export type Instrument = {
  slug: string
  short_title: string
  title: string
  citation: string
  instrument_type: string
  status: string
  official_url: string
  adopted_on: string | null
  applies_from: string | null
  transposition_deadline: string | null
  last_verified_on: string
  notes: string | null
  jurisdiction_code: string
  jurisdiction_name: string
  requirement_count: number
}

export type Jurisdiction = {
  code: string
  name: string
  level: string
  notes: string | null
  instrument_count: number
  overlay_count: number
}

type ApiState<T> = {
  data: T | null
  error: boolean
  loading: boolean
}

export function useApi<T>(url: string): ApiState<T> {
  const [state, setState] = useState<ApiState<T>>({ data: null, error: false, loading: true })

  useEffect(() => {
    const controller = new AbortController()
    setState((current) => ({ ...current, error: false, loading: true }))

    fetch(url, { signal: controller.signal })
      .then((response) => {
        if (!response.ok) throw new Error(`Request failed with ${response.status}`)
        return response.json() as Promise<T>
      })
      .then((data) => setState({ data, error: false, loading: false }))
      .catch((error: Error) => {
        if (error.name !== 'AbortError') setState({ data: null, error: true, loading: false })
      })

    return () => controller.abort()
  }, [url])

  return state
}
