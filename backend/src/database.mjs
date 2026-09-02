import { DatabaseSync } from 'node:sqlite'

const delimiter = '|||'

function splitList(value) {
  return value ? value.split(delimiter) : []
}

function searchExpression(value) {
  const tokens = value
    .normalize('NFKC')
    .toLocaleLowerCase('en')
    .match(/[\p{L}\p{N}]+/gu)
    ?.slice(0, 8)
    .map((token) => `${token.slice(0, 64)}*`)

  return tokens?.join(' AND ') || null
}

function normalizeRequirement(row) {
  return {
    ...row,
    is_generated: Boolean(row.is_generated),
    hiring_stages: splitList(row.hiring_stages),
    legal_lenses: splitList(row.legal_lenses),
    actors: splitList(row.actors),
  }
}

function requirementSelect() {
  return `
    SELECT
      r.id,
      r.slug,
      r.title,
      r.plain_summary,
      r.source_locator,
      r.legal_effect,
      r.status,
      r.effective_from,
      r.effective_note,
      r.compliance_action,
      r.escalation_trigger,
      r.review_status,
      r.is_generated,
      r.last_reviewed_on,
      i.slug AS instrument_slug,
      i.short_title AS instrument_short_title,
      i.title AS instrument_title,
      i.citation,
      i.instrument_type,
      i.official_url,
      i.last_verified_on AS source_last_verified_on,
      j.code AS jurisdiction_code,
      j.name AS jurisdiction_name,
      (
        SELECT GROUP_CONCAT(name, '${delimiter}')
        FROM (
          SELECT hs.name
          FROM requirement_hiring_stages rhs
          JOIN hiring_stages hs ON hs.id = rhs.hiring_stage_id
          WHERE rhs.requirement_id = r.id
          ORDER BY hs.position
        )
      ) AS hiring_stages,
      (
        SELECT GROUP_CONCAT(name, '${delimiter}')
        FROM (
          SELECT ll.name
          FROM requirement_legal_lenses rll
          JOIN legal_lenses ll ON ll.id = rll.legal_lens_id
          WHERE rll.requirement_id = r.id
          ORDER BY ll.position
        )
      ) AS legal_lenses,
      (
        SELECT GROUP_CONCAT(name, '${delimiter}')
        FROM (
          SELECT a.name
          FROM requirement_actors ra
          JOIN actors a ON a.id = ra.actor_id
          WHERE ra.requirement_id = r.id
          ORDER BY a.name
        )
      ) AS actors
    FROM requirements r
    JOIN legal_instruments i ON i.id = r.instrument_id
    JOIN jurisdictions j ON j.id = i.jurisdiction_id
  `
}

export function createRepository(databasePath) {
  const database = new DatabaseSync(databasePath, { readOnly: true })
  database.exec('PRAGMA foreign_keys = ON')

  function listRequirements({ q = '', stage = '', lens = '', effect = '', status = '', page = 1, pageSize = 25 } = {}) {
    const conditions = []
    const parameters = []
    const fts = searchExpression(q)

    if (fts) {
      conditions.push('r.id IN (SELECT rowid FROM requirement_search WHERE requirement_search MATCH ?)')
      parameters.push(fts)
    }
    if (stage) {
      conditions.push(`EXISTS (
        SELECT 1
        FROM requirement_hiring_stages rhs
        JOIN hiring_stages hs ON hs.id = rhs.hiring_stage_id
        WHERE rhs.requirement_id = r.id AND hs.slug = ?
      )`)
      parameters.push(stage)
    }
    if (lens) {
      conditions.push(`EXISTS (
        SELECT 1
        FROM requirement_legal_lenses rll
        JOIN legal_lenses ll ON ll.id = rll.legal_lens_id
        WHERE rll.requirement_id = r.id AND ll.slug = ?
      )`)
      parameters.push(lens)
    }
    if (effect) {
      conditions.push('r.legal_effect = ?')
      parameters.push(effect)
    }
    if (status) {
      conditions.push('r.status = ?')
      parameters.push(status)
    }

    const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : ''
    const safePage = Math.max(1, Number.isInteger(page) ? page : 1)
    const safePageSize = Math.min(100, Math.max(1, Number.isInteger(pageSize) ? pageSize : 25))
    const total = database.prepare(`SELECT COUNT(*) AS count FROM requirements r ${where}`).get(...parameters).count
    const rows = database.prepare(`
      ${requirementSelect()}
      ${where}
      ORDER BY
        CASE r.status WHEN 'current' THEN 1 WHEN 'country_transposition' THEN 2 WHEN 'upcoming' THEN 3 ELSE 4 END,
        r.title
      LIMIT ? OFFSET ?
    `).all(...parameters, safePageSize, (safePage - 1) * safePageSize)

    return {
      items: rows.map(normalizeRequirement),
      page: safePage,
      page_size: safePageSize,
      total,
      total_pages: Math.max(1, Math.ceil(total / safePageSize)),
    }
  }

  function getRequirement(slug) {
    const row = database.prepare(`${requirementSelect()} WHERE r.slug = ?`).get(slug)
    if (!row) return null

    const relations = database.prepare(`
      SELECT
        related.slug,
        related.title,
        relation.relation_type,
        relation.notes,
        'outgoing' AS direction
      FROM requirement_relations relation
      JOIN requirements related ON related.id = relation.to_requirement_id
      WHERE relation.from_requirement_id = ?
      UNION ALL
      SELECT
        related.slug,
        related.title,
        relation.relation_type,
        relation.notes,
        'incoming' AS direction
      FROM requirement_relations relation
      JOIN requirements related ON related.id = relation.from_requirement_id
      WHERE relation.to_requirement_id = ?
      ORDER BY title
    `).all(row.id, row.id)

    return { ...normalizeRequirement(row), relations }
  }

  function getOverview() {
    return {
      requirements: database.prepare('SELECT COUNT(*) AS count FROM requirements').get().count,
      official_sources: database.prepare('SELECT COUNT(*) AS count FROM legal_instruments').get().count,
      jurisdictions: database.prepare('SELECT COUNT(*) AS count FROM jurisdictions').get().count,
      last_verified_on: database.prepare('SELECT MAX(last_verified_on) AS date FROM legal_instruments').get().date,
    }
  }

  function getTaxonomies() {
    return {
      hiring_stages: database.prepare('SELECT slug, name FROM hiring_stages ORDER BY position').all(),
      legal_lenses: database.prepare('SELECT slug, name FROM legal_lenses ORDER BY position').all(),
      legal_effects: database.prepare(`
        SELECT legal_effect AS slug, COUNT(*) AS count
        FROM requirements
        GROUP BY legal_effect
        ORDER BY legal_effect
      `).all(),
      statuses: database.prepare(`
        SELECT status AS slug, COUNT(*) AS count
        FROM requirements
        GROUP BY status
        ORDER BY status
      `).all(),
    }
  }

  function listInstruments() {
    return database.prepare(`
      SELECT
        i.slug,
        i.short_title,
        i.title,
        i.citation,
        i.instrument_type,
        i.status,
        i.official_url,
        i.adopted_on,
        i.applies_from,
        i.transposition_deadline,
        i.last_verified_on,
        i.notes,
        j.code AS jurisdiction_code,
        j.name AS jurisdiction_name,
        COUNT(r.id) AS requirement_count
      FROM legal_instruments i
      JOIN jurisdictions j ON j.id = i.jurisdiction_id
      LEFT JOIN requirements r ON r.instrument_id = i.id
      GROUP BY i.id
      ORDER BY i.short_title
    `).all()
  }

  function listJurisdictions() {
    return database.prepare(`
      SELECT
        j.code,
        j.name,
        j.level,
        j.notes,
        COUNT(DISTINCT i.id) AS instrument_count,
        COUNT(DISTINCT o.id) AS overlay_count
      FROM jurisdictions j
      LEFT JOIN legal_instruments i ON i.jurisdiction_id = j.id
      LEFT JOIN country_overlays o ON o.jurisdiction_id = j.id
      GROUP BY j.id
      ORDER BY j.level, j.name
    `).all()
  }

  return {
    close: () => database.close(),
    getOverview,
    getRequirement,
    getTaxonomies,
    listInstruments,
    listJurisdictions,
    listRequirements,
  }
}
