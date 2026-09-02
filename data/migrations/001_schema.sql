PRAGMA foreign_keys = ON;

CREATE TABLE jurisdictions (
  id INTEGER PRIMARY KEY,
  code TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  level TEXT NOT NULL CHECK (level IN ('eu', 'member_state', 'regional', 'international')),
  parent_id INTEGER REFERENCES jurisdictions(id),
  notes TEXT
);

CREATE TABLE legal_instruments (
  id INTEGER PRIMARY KEY,
  slug TEXT NOT NULL UNIQUE,
  title TEXT NOT NULL,
  short_title TEXT NOT NULL,
  citation TEXT NOT NULL,
  instrument_type TEXT NOT NULL CHECK (
    instrument_type IN ('treaty', 'charter', 'regulation', 'directive', 'case_law', 'guidance', 'standard', 'national_law')
  ),
  jurisdiction_id INTEGER NOT NULL REFERENCES jurisdictions(id),
  status TEXT NOT NULL CHECK (status IN ('in_force', 'upcoming', 'transposition', 'guidance', 'proposal', 'superseded')),
  official_url TEXT NOT NULL,
  adopted_on TEXT,
  applies_from TEXT,
  transposition_deadline TEXT,
  last_verified_on TEXT NOT NULL,
  notes TEXT
);

CREATE TABLE requirements (
  id INTEGER PRIMARY KEY,
  slug TEXT NOT NULL UNIQUE,
  instrument_id INTEGER NOT NULL REFERENCES legal_instruments(id),
  title TEXT NOT NULL,
  plain_summary TEXT NOT NULL,
  source_locator TEXT NOT NULL,
  legal_effect TEXT NOT NULL CHECK (
    legal_effect IN ('required', 'prohibited', 'permitted_with_conditions', 'good_practice', 'country_review')
  ),
  status TEXT NOT NULL CHECK (status IN ('current', 'upcoming', 'country_transposition', 'guidance', 'proposal')),
  effective_from TEXT,
  effective_note TEXT,
  compliance_action TEXT NOT NULL,
  escalation_trigger TEXT,
  review_status TEXT NOT NULL DEFAULT 'research_only' CHECK (
    review_status IN ('research_only', 'expert_reviewed', 'local_validation_needed')
  ),
  is_generated INTEGER NOT NULL DEFAULT 0 CHECK (is_generated IN (0, 1)),
  last_reviewed_on TEXT NOT NULL
);

CREATE TABLE hiring_stages (
  id INTEGER PRIMARY KEY,
  slug TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  position INTEGER NOT NULL UNIQUE
);

CREATE TABLE legal_lenses (
  id INTEGER PRIMARY KEY,
  slug TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  position INTEGER NOT NULL UNIQUE
);

CREATE TABLE actors (
  id INTEGER PRIMARY KEY,
  slug TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL
);

CREATE TABLE requirement_hiring_stages (
  requirement_id INTEGER NOT NULL REFERENCES requirements(id) ON DELETE CASCADE,
  hiring_stage_id INTEGER NOT NULL REFERENCES hiring_stages(id) ON DELETE CASCADE,
  PRIMARY KEY (requirement_id, hiring_stage_id)
);

CREATE TABLE requirement_legal_lenses (
  requirement_id INTEGER NOT NULL REFERENCES requirements(id) ON DELETE CASCADE,
  legal_lens_id INTEGER NOT NULL REFERENCES legal_lenses(id) ON DELETE CASCADE,
  PRIMARY KEY (requirement_id, legal_lens_id)
);

CREATE TABLE requirement_actors (
  requirement_id INTEGER NOT NULL REFERENCES requirements(id) ON DELETE CASCADE,
  actor_id INTEGER NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
  PRIMARY KEY (requirement_id, actor_id)
);

CREATE TABLE requirement_relations (
  from_requirement_id INTEGER NOT NULL REFERENCES requirements(id) ON DELETE CASCADE,
  to_requirement_id INTEGER NOT NULL REFERENCES requirements(id) ON DELETE CASCADE,
  relation_type TEXT NOT NULL CHECK (relation_type IN ('overlaps', 'implements', 'limits', 'depends_on', 'compare_with')),
  notes TEXT,
  PRIMARY KEY (from_requirement_id, to_requirement_id, relation_type),
  CHECK (from_requirement_id <> to_requirement_id)
);

CREATE TABLE country_overlays (
  id INTEGER PRIMARY KEY,
  jurisdiction_id INTEGER NOT NULL REFERENCES jurisdictions(id),
  requirement_id INTEGER REFERENCES requirements(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  summary TEXT NOT NULL,
  official_url TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('current', 'upcoming', 'proposal', 'needs_validation')),
  effective_from TEXT,
  last_verified_on TEXT NOT NULL
);

CREATE TABLE source_checks (
  id INTEGER PRIMARY KEY,
  instrument_id INTEGER NOT NULL REFERENCES legal_instruments(id) ON DELETE CASCADE,
  checked_on TEXT NOT NULL,
  check_status TEXT NOT NULL CHECK (check_status IN ('current', 'changed', 'unavailable', 'needs_review')),
  notes TEXT,
  UNIQUE (instrument_id, checked_on)
);

CREATE INDEX requirements_instrument_id_idx ON requirements(instrument_id);
CREATE INDEX requirements_effect_idx ON requirements(legal_effect);
CREATE INDEX requirements_status_idx ON requirements(status);
CREATE INDEX requirement_stages_stage_idx ON requirement_hiring_stages(hiring_stage_id);
CREATE INDEX requirement_lenses_lens_idx ON requirement_legal_lenses(legal_lens_id);
CREATE INDEX requirement_actors_actor_idx ON requirement_actors(actor_id);
CREATE INDEX country_overlays_jurisdiction_idx ON country_overlays(jurisdiction_id);

CREATE VIRTUAL TABLE requirement_search USING fts5(
  title,
  plain_summary,
  compliance_action,
  content = 'requirements',
  content_rowid = 'id',
  tokenize = 'unicode61 remove_diacritics 2'
);

CREATE TRIGGER requirements_search_insert AFTER INSERT ON requirements BEGIN
  INSERT INTO requirement_search(rowid, title, plain_summary, compliance_action)
  VALUES (new.id, new.title, new.plain_summary, new.compliance_action);
END;

CREATE TRIGGER requirements_search_delete AFTER DELETE ON requirements BEGIN
  INSERT INTO requirement_search(requirement_search, rowid, title, plain_summary, compliance_action)
  VALUES ('delete', old.id, old.title, old.plain_summary, old.compliance_action);
END;

CREATE TRIGGER requirements_search_update AFTER UPDATE ON requirements BEGIN
  INSERT INTO requirement_search(requirement_search, rowid, title, plain_summary, compliance_action)
  VALUES ('delete', old.id, old.title, old.plain_summary, old.compliance_action);
  INSERT INTO requirement_search(rowid, title, plain_summary, compliance_action)
  VALUES (new.id, new.title, new.plain_summary, new.compliance_action);
END;
