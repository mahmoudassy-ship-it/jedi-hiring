PRAGMA foreign_keys = ON;

CREATE TABLE atlas_principals (
  id INTEGER PRIMARY KEY,
  principal_code TEXT NOT NULL UNIQUE,
  principal_kind_code TEXT NOT NULL CHECK (principal_kind_code IN ('human', 'service')),
  display_name TEXT NOT NULL,
  external_subject TEXT UNIQUE,
  created_at TEXT NOT NULL CHECK (
    length(created_at) = 24
    AND created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'
    AND julianday(created_at) IS NOT NULL
    AND strftime('%Y-%m-%dT%H:%M:%fZ', julianday(created_at)) = created_at
  ),
  CHECK (principal_code = lower(principal_code) AND principal_code <> '' AND principal_code NOT GLOB '*[^a-z0-9._-]*')
);

CREATE TABLE atlas_principal_status_events (
  id INTEGER PRIMARY KEY,
  principal_id INTEGER NOT NULL REFERENCES atlas_principals(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  status_code TEXT NOT NULL CHECK (status_code IN ('active', 'retired', 'replaced')),
  replacement_principal_id INTEGER REFERENCES atlas_principals(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  effective_on TEXT NOT NULL CHECK (
    length(effective_on) = 10
    AND effective_on GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'
    AND julianday(effective_on) IS NOT NULL
    AND date(julianday(effective_on)) = effective_on
  ),
  recorded_at TEXT NOT NULL CHECK (
    length(recorded_at) = 24
    AND recorded_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'
    AND julianday(recorded_at) IS NOT NULL
    AND strftime('%Y-%m-%dT%H:%M:%fZ', julianday(recorded_at)) = recorded_at
  ),
  reason TEXT NOT NULL,
  UNIQUE (principal_id, effective_on, recorded_at),
  CHECK (
    (status_code = 'replaced' AND replacement_principal_id IS NOT NULL AND replacement_principal_id <> principal_id)
    OR (status_code IN ('active', 'retired') AND replacement_principal_id IS NULL)
  )
);

CREATE TABLE atlas_languages (
  id INTEGER PRIMARY KEY,
  language_code TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  created_at TEXT NOT NULL CHECK (
    length(created_at) = 24
    AND created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'
    AND julianday(created_at) IS NOT NULL
    AND strftime('%Y-%m-%dT%H:%M:%fZ', julianday(created_at)) = created_at
  ),
  CHECK (language_code = lower(language_code) AND length(language_code) BETWEEN 2 AND 35 AND language_code NOT GLOB '*[^a-z0-9-]*')
);

CREATE TABLE atlas_jurisdictions (
  id INTEGER PRIMARY KEY,
  jurisdiction_code TEXT NOT NULL UNIQUE,
  jurisdiction_kind_code TEXT NOT NULL CHECK (jurisdiction_kind_code IN ('supranational', 'state', 'regional', 'devolved', 'local')),
  created_at TEXT NOT NULL CHECK (
    length(created_at) = 24
    AND created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'
    AND julianday(created_at) IS NOT NULL
    AND strftime('%Y-%m-%dT%H:%M:%fZ', julianday(created_at)) = created_at
  ),
  CHECK (jurisdiction_code = lower(jurisdiction_code) AND jurisdiction_code <> '' AND jurisdiction_code NOT GLOB '*[^a-z0-9._-]*')
);

CREATE TABLE atlas_jurisdiction_status_events (
  id INTEGER PRIMARY KEY,
  jurisdiction_id INTEGER NOT NULL REFERENCES atlas_jurisdictions(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  status_code TEXT NOT NULL CHECK (status_code IN ('active', 'retired', 'replaced')),
  replacement_jurisdiction_id INTEGER REFERENCES atlas_jurisdictions(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  effective_on TEXT NOT NULL CHECK (
    length(effective_on) = 10
    AND effective_on GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'
    AND julianday(effective_on) IS NOT NULL
    AND date(julianday(effective_on)) = effective_on
  ),
  recorded_at TEXT NOT NULL CHECK (
    length(recorded_at) = 24
    AND recorded_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'
    AND julianday(recorded_at) IS NOT NULL
    AND strftime('%Y-%m-%dT%H:%M:%fZ', julianday(recorded_at)) = recorded_at
  ),
  reason TEXT NOT NULL,
  UNIQUE (jurisdiction_id, effective_on, recorded_at),
  CHECK (
    (status_code = 'replaced' AND replacement_jurisdiction_id IS NOT NULL AND replacement_jurisdiction_id <> jurisdiction_id)
    OR (status_code IN ('active', 'retired') AND replacement_jurisdiction_id IS NULL)
  )
);

CREATE TABLE atlas_jurisdiction_versions (
  id INTEGER PRIMARY KEY,
  jurisdiction_id INTEGER NOT NULL REFERENCES atlas_jurisdictions(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  language_id INTEGER NOT NULL REFERENCES atlas_languages(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  name TEXT NOT NULL,
  description TEXT,
  effective_from TEXT NOT NULL CHECK (
    length(effective_from) = 10
    AND effective_from GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'
    AND julianday(effective_from) IS NOT NULL
    AND date(julianday(effective_from)) = effective_from
  ),
  recorded_at TEXT NOT NULL CHECK (
    length(recorded_at) = 24
    AND recorded_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'
    AND julianday(recorded_at) IS NOT NULL
    AND strftime('%Y-%m-%dT%H:%M:%fZ', julianday(recorded_at)) = recorded_at
  ),
  content_sha256 TEXT NOT NULL CHECK (
    length(content_sha256) = 64
    AND content_sha256 = lower(content_sha256)
    AND content_sha256 NOT GLOB '*[^0-9a-f]*'
  ),
  supersedes_jurisdiction_version_id INTEGER UNIQUE REFERENCES atlas_jurisdiction_versions(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  UNIQUE (jurisdiction_id, language_id, effective_from, recorded_at),
  CHECK (supersedes_jurisdiction_version_id IS NULL OR supersedes_jurisdiction_version_id <> id)
);

CREATE TABLE atlas_jurisdiction_external_identifiers (
  id INTEGER PRIMARY KEY,
  jurisdiction_id INTEGER NOT NULL REFERENCES atlas_jurisdictions(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  scheme_code TEXT NOT NULL,
  identifier_value TEXT NOT NULL,
  effective_from TEXT NOT NULL CHECK (
    length(effective_from) = 10
    AND effective_from GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'
    AND julianday(effective_from) IS NOT NULL
    AND date(julianday(effective_from)) = effective_from
  ),
  recorded_at TEXT NOT NULL CHECK (
    length(recorded_at) = 24
    AND recorded_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'
    AND julianday(recorded_at) IS NOT NULL
    AND strftime('%Y-%m-%dT%H:%M:%fZ', julianday(recorded_at)) = recorded_at
  ),
  supersedes_external_identifier_id INTEGER UNIQUE REFERENCES atlas_jurisdiction_external_identifiers(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  UNIQUE (scheme_code, identifier_value, effective_from, recorded_at),
  CHECK (scheme_code = lower(scheme_code) AND scheme_code <> '' AND scheme_code NOT GLOB '*[^a-z0-9._-]*'),
  CHECK (identifier_value <> ''),
  CHECK (supersedes_external_identifier_id IS NULL OR supersedes_external_identifier_id <> id)
);

CREATE INDEX atlas_principal_status_events_as_of_idx ON atlas_principal_status_events(principal_id, effective_on DESC, recorded_at DESC, id DESC);
CREATE INDEX atlas_jurisdiction_status_events_as_of_idx ON atlas_jurisdiction_status_events(jurisdiction_id, effective_on DESC, recorded_at DESC, id DESC);
CREATE INDEX atlas_jurisdiction_versions_as_of_idx ON atlas_jurisdiction_versions(jurisdiction_id, language_id, effective_from DESC, recorded_at DESC, id DESC);
CREATE INDEX atlas_jurisdiction_external_identifiers_as_of_idx ON atlas_jurisdiction_external_identifiers(jurisdiction_id, scheme_code, effective_from DESC, recorded_at DESC, id DESC);
CREATE INDEX atlas_jurisdiction_external_identifiers_lookup_idx ON atlas_jurisdiction_external_identifiers(scheme_code, identifier_value, effective_from DESC);

CREATE TRIGGER atlas_principals_immutable_update BEFORE UPDATE ON atlas_principals BEGIN SELECT RAISE(ABORT, 'principal identities are immutable'); END;
CREATE TRIGGER atlas_principals_immutable_delete BEFORE DELETE ON atlas_principals BEGIN SELECT RAISE(ABORT, 'principal identities are immutable'); END;
CREATE TRIGGER atlas_principal_status_events_append_only_update BEFORE UPDATE ON atlas_principal_status_events BEGIN SELECT RAISE(ABORT, 'principal status events are append-only'); END;
CREATE TRIGGER atlas_principal_status_events_append_only_delete BEFORE DELETE ON atlas_principal_status_events BEGIN SELECT RAISE(ABORT, 'principal status events are append-only'); END;
CREATE TRIGGER atlas_languages_immutable_update BEFORE UPDATE ON atlas_languages BEGIN SELECT RAISE(ABORT, 'language identities are immutable'); END;
CREATE TRIGGER atlas_languages_immutable_delete BEFORE DELETE ON atlas_languages BEGIN SELECT RAISE(ABORT, 'language identities are immutable'); END;
CREATE TRIGGER atlas_jurisdictions_immutable_update BEFORE UPDATE ON atlas_jurisdictions BEGIN SELECT RAISE(ABORT, 'jurisdiction identities are immutable'); END;
CREATE TRIGGER atlas_jurisdictions_immutable_delete BEFORE DELETE ON atlas_jurisdictions BEGIN SELECT RAISE(ABORT, 'jurisdiction identities are immutable'); END;
CREATE TRIGGER atlas_jurisdiction_status_events_append_only_update BEFORE UPDATE ON atlas_jurisdiction_status_events BEGIN SELECT RAISE(ABORT, 'jurisdiction status events are append-only'); END;
CREATE TRIGGER atlas_jurisdiction_status_events_append_only_delete BEFORE DELETE ON atlas_jurisdiction_status_events BEGIN SELECT RAISE(ABORT, 'jurisdiction status events are append-only'); END;
CREATE TRIGGER atlas_jurisdiction_versions_immutable_update BEFORE UPDATE ON atlas_jurisdiction_versions BEGIN SELECT RAISE(ABORT, 'jurisdiction versions are immutable'); END;
CREATE TRIGGER atlas_jurisdiction_versions_immutable_delete BEFORE DELETE ON atlas_jurisdiction_versions BEGIN SELECT RAISE(ABORT, 'jurisdiction versions are immutable'); END;
CREATE TRIGGER atlas_jurisdiction_external_identifiers_immutable_update BEFORE UPDATE ON atlas_jurisdiction_external_identifiers BEGIN SELECT RAISE(ABORT, 'jurisdiction external identifiers are immutable'); END;
CREATE TRIGGER atlas_jurisdiction_external_identifiers_immutable_delete BEFORE DELETE ON atlas_jurisdiction_external_identifiers BEGIN SELECT RAISE(ABORT, 'jurisdiction external identifiers are immutable'); END;

CREATE TRIGGER atlas_principal_status_events_prevent_replacement_cycles
BEFORE INSERT ON atlas_principal_status_events WHEN NEW.replacement_principal_id IS NOT NULL
BEGIN
  SELECT CASE WHEN EXISTS (
    WITH RECURSIVE replacements(id) AS (
      SELECT replacement_principal_id FROM atlas_principal_status_events WHERE principal_id = NEW.replacement_principal_id AND replacement_principal_id IS NOT NULL
      UNION
      SELECT e.replacement_principal_id FROM atlas_principal_status_events e JOIN replacements r ON e.principal_id = r.id WHERE e.replacement_principal_id IS NOT NULL
    ) SELECT 1 FROM replacements WHERE id = NEW.principal_id
  ) THEN RAISE(ABORT, 'principal replacement cycle') END;
END;

CREATE TRIGGER atlas_jurisdiction_status_events_prevent_replacement_cycles
BEFORE INSERT ON atlas_jurisdiction_status_events WHEN NEW.replacement_jurisdiction_id IS NOT NULL
BEGIN
  SELECT CASE WHEN EXISTS (
    WITH RECURSIVE replacements(id) AS (
      SELECT replacement_jurisdiction_id FROM atlas_jurisdiction_status_events WHERE jurisdiction_id = NEW.replacement_jurisdiction_id AND replacement_jurisdiction_id IS NOT NULL
      UNION
      SELECT e.replacement_jurisdiction_id FROM atlas_jurisdiction_status_events e JOIN replacements r ON e.jurisdiction_id = r.id WHERE e.replacement_jurisdiction_id IS NOT NULL
    ) SELECT 1 FROM replacements WHERE id = NEW.jurisdiction_id
  ) THEN RAISE(ABORT, 'jurisdiction replacement cycle') END;
END;

CREATE TRIGGER atlas_jurisdiction_versions_validate_successor
BEFORE INSERT ON atlas_jurisdiction_versions WHEN NEW.supersedes_jurisdiction_version_id IS NOT NULL
BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM atlas_jurisdiction_versions previous
    WHERE previous.id = NEW.supersedes_jurisdiction_version_id
      AND previous.jurisdiction_id = NEW.jurisdiction_id
      AND previous.language_id = NEW.language_id
  ) THEN RAISE(ABORT, 'jurisdiction version must supersede the same jurisdiction and language') END;
  SELECT CASE WHEN EXISTS (
    WITH RECURSIVE predecessors(id) AS (
      SELECT supersedes_jurisdiction_version_id FROM atlas_jurisdiction_versions WHERE id = NEW.supersedes_jurisdiction_version_id
      UNION
      SELECT v.supersedes_jurisdiction_version_id FROM atlas_jurisdiction_versions v JOIN predecessors p ON v.id = p.id WHERE v.supersedes_jurisdiction_version_id IS NOT NULL
    ) SELECT 1 FROM predecessors WHERE id = NEW.id
  ) THEN RAISE(ABORT, 'jurisdiction version supersession cycle') END;
END;

CREATE TRIGGER atlas_jurisdiction_external_identifiers_validate_successor
BEFORE INSERT ON atlas_jurisdiction_external_identifiers WHEN NEW.supersedes_external_identifier_id IS NOT NULL
BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM atlas_jurisdiction_external_identifiers previous
    WHERE previous.id = NEW.supersedes_external_identifier_id
      AND previous.jurisdiction_id = NEW.jurisdiction_id
      AND previous.scheme_code = NEW.scheme_code
  ) THEN RAISE(ABORT, 'external identifier must supersede the same jurisdiction and scheme') END;
  SELECT CASE WHEN EXISTS (
    WITH RECURSIVE predecessors(id) AS (
      SELECT supersedes_external_identifier_id FROM atlas_jurisdiction_external_identifiers WHERE id = NEW.supersedes_external_identifier_id
      UNION
      SELECT e.supersedes_external_identifier_id FROM atlas_jurisdiction_external_identifiers e JOIN predecessors p ON e.id = p.id WHERE e.supersedes_external_identifier_id IS NOT NULL
    ) SELECT 1 FROM predecessors WHERE id = NEW.id
  ) THEN RAISE(ABORT, 'external identifier supersession cycle') END;
END;
