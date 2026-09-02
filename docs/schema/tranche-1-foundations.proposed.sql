PRAGMA foreign_keys = ON;
PRAGMA recursive_triggers = ON;

CREATE TABLE atlas_principals (
  id INTEGER PRIMARY KEY,
  principal_code TEXT NOT NULL UNIQUE,
  principal_kind_code TEXT NOT NULL CHECK (principal_kind_code IN ('human', 'service')),
  created_by_principal_id INTEGER NOT NULL REFERENCES atlas_principals(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  created_at TEXT NOT NULL CHECK (
    length(CAST(created_at AS BLOB)) = 24
    AND instr(created_at, char(0)) = 0
    AND created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'
    AND julianday(created_at) IS NOT NULL
    AND strftime('%Y-%m-%dT%H:%M:%fZ', julianday(created_at)) = created_at
  ),
  CHECK (
    length(CAST(principal_code AS BLOB)) BETWEEN 1 AND 80
    AND instr(principal_code, char(0)) = 0
    AND principal_code = trim(principal_code)
    AND principal_code = lower(principal_code)
    AND principal_code NOT GLOB '*[^a-z0-9._-]*'
  )
) STRICT;

CREATE TABLE atlas_languages (
  id INTEGER PRIMARY KEY,
  language_code TEXT NOT NULL UNIQUE,
  recorded_by_principal_id INTEGER NOT NULL REFERENCES atlas_principals(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  recorded_at TEXT NOT NULL CHECK (
    length(CAST(recorded_at AS BLOB)) = 24
    AND instr(recorded_at, char(0)) = 0
    AND recorded_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'
    AND julianday(recorded_at) IS NOT NULL
    AND strftime('%Y-%m-%dT%H:%M:%fZ', julianday(recorded_at)) = recorded_at
  ),
  CHECK (
    length(CAST(language_code AS BLOB)) BETWEEN 2 AND 35
    AND instr(language_code, char(0)) = 0
    AND language_code = trim(language_code)
    AND language_code NOT LIKE '-%'
    AND language_code NOT LIKE '%-'
    AND language_code NOT LIKE '%--%'
    AND language_code GLOB '[A-Za-z][A-Za-z]*'
    AND language_code NOT GLOB '*[^A-Za-z0-9-]*'
  )
) STRICT;

CREATE TABLE atlas_jurisdictions (
  id INTEGER PRIMARY KEY,
  jurisdiction_code TEXT NOT NULL UNIQUE,
  jurisdiction_kind_code TEXT NOT NULL CHECK (
    jurisdiction_kind_code IN ('international', 'supranational', 'state', 'territory', 'regional', 'devolved', 'local')
  ),
  recorded_by_principal_id INTEGER NOT NULL REFERENCES atlas_principals(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  recorded_at TEXT NOT NULL CHECK (
    length(CAST(recorded_at AS BLOB)) = 24
    AND instr(recorded_at, char(0)) = 0
    AND recorded_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'
    AND julianday(recorded_at) IS NOT NULL
    AND strftime('%Y-%m-%dT%H:%M:%fZ', julianday(recorded_at)) = recorded_at
  ),
  CHECK (
    length(CAST(jurisdiction_code AS BLOB)) BETWEEN 1 AND 80
    AND instr(jurisdiction_code, char(0)) = 0
    AND jurisdiction_code = trim(jurisdiction_code)
    AND jurisdiction_code = lower(jurisdiction_code)
    AND jurisdiction_code NOT GLOB '*[^a-z0-9._-]*'
  )
) STRICT;

CREATE TABLE atlas_jurisdiction_versions (
  id INTEGER PRIMARY KEY,
  jurisdiction_id INTEGER NOT NULL REFERENCES atlas_jurisdictions(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  language_id INTEGER NOT NULL REFERENCES atlas_languages(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  effective_from TEXT NOT NULL CHECK (
    length(CAST(effective_from AS BLOB)) = 10
    AND instr(effective_from, char(0)) = 0
    AND effective_from GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'
    AND julianday(effective_from) IS NOT NULL
    AND date(julianday(effective_from)) = effective_from
  ),
  record_kind_code TEXT NOT NULL CHECK (record_kind_code IN ('assertion', 'correction', 'withdrawal')),
  name TEXT,
  description TEXT,
  corrects_jurisdiction_version_id INTEGER UNIQUE REFERENCES atlas_jurisdiction_versions(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  reason TEXT NOT NULL,
  recorded_by_principal_id INTEGER NOT NULL REFERENCES atlas_principals(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  recorded_at TEXT NOT NULL CHECK (
    length(CAST(recorded_at AS BLOB)) = 24
    AND instr(recorded_at, char(0)) = 0
    AND recorded_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'
    AND julianday(recorded_at) IS NOT NULL
    AND strftime('%Y-%m-%dT%H:%M:%fZ', julianday(recorded_at)) = recorded_at
  ),
  CHECK (
    length(CAST(reason AS BLOB)) > 0
    AND instr(reason, char(0)) = 0
    AND trim(reason) <> ''
  ),
  CHECK (
    (record_kind_code = 'assertion' AND corrects_jurisdiction_version_id IS NULL AND name IS NOT NULL)
    OR (record_kind_code = 'correction' AND corrects_jurisdiction_version_id IS NOT NULL AND name IS NOT NULL)
    OR (record_kind_code = 'withdrawal' AND corrects_jurisdiction_version_id IS NOT NULL AND name IS NULL AND description IS NULL)
  ),
  CHECK (
    name IS NULL OR (
      length(CAST(name AS BLOB)) > 0
      AND instr(name, char(0)) = 0
      AND trim(name) <> ''
    )
  ),
  CHECK (description IS NULL OR instr(description, char(0)) = 0),
  CHECK (corrects_jurisdiction_version_id IS NULL OR corrects_jurisdiction_version_id <> id)
) STRICT;

CREATE UNIQUE INDEX atlas_jurisdiction_versions_one_root_idx
ON atlas_jurisdiction_versions(jurisdiction_id, language_id, effective_from)
WHERE record_kind_code = 'assertion';

CREATE INDEX atlas_jurisdiction_versions_bitemporal_idx
ON atlas_jurisdiction_versions(jurisdiction_id, language_id, effective_from DESC, recorded_at DESC, id DESC);

CREATE INDEX atlas_jurisdiction_versions_correction_idx
ON atlas_jurisdiction_versions(corrects_jurisdiction_version_id, recorded_at, id);

CREATE TRIGGER atlas_principals_bootstrap_guard
BEFORE INSERT ON atlas_principals
WHEN NOT EXISTS (SELECT 1 FROM atlas_principals)
  AND NOT (
    NEW.id = 1
    AND NEW.principal_code = 'bootstrap'
    AND NEW.principal_kind_code = 'human'
    AND NEW.created_by_principal_id = NEW.id
  )
BEGIN SELECT RAISE(ABORT, 'first principal must be the explicit self-attributed human bootstrap identity'); END;

CREATE TRIGGER atlas_principals_attribution_guard
BEFORE INSERT ON atlas_principals
WHEN EXISTS (SELECT 1 FROM atlas_principals)
  AND NEW.created_by_principal_id = NEW.id
BEGIN SELECT RAISE(ABORT, 'subsequent principals require a different recorded creator'); END;

CREATE TRIGGER atlas_principals_collision_guard
BEFORE INSERT ON atlas_principals
WHEN EXISTS (SELECT 1 FROM atlas_principals WHERE id = NEW.id OR principal_code = NEW.principal_code)
BEGIN SELECT RAISE(ABORT, 'principal identity collision'); END;

CREATE TRIGGER atlas_languages_collision_guard
BEFORE INSERT ON atlas_languages
WHEN EXISTS (SELECT 1 FROM atlas_languages WHERE id = NEW.id OR language_code = NEW.language_code)
BEGIN SELECT RAISE(ABORT, 'language identity collision'); END;

CREATE TRIGGER atlas_jurisdictions_collision_guard
BEFORE INSERT ON atlas_jurisdictions
WHEN EXISTS (SELECT 1 FROM atlas_jurisdictions WHERE id = NEW.id OR jurisdiction_code = NEW.jurisdiction_code)
BEGIN SELECT RAISE(ABORT, 'jurisdiction identity collision'); END;

CREATE TRIGGER atlas_jurisdiction_versions_collision_guard
BEFORE INSERT ON atlas_jurisdiction_versions
WHEN EXISTS (SELECT 1 FROM atlas_jurisdiction_versions WHERE id = NEW.id)
BEGIN SELECT RAISE(ABORT, 'jurisdiction version identity collision'); END;

CREATE TRIGGER atlas_jurisdiction_versions_validate_insert
BEFORE INSERT ON atlas_jurisdiction_versions
BEGIN
  SELECT CASE WHEN NEW.record_kind_code = 'assertion' AND EXISTS (
    SELECT 1 FROM atlas_jurisdiction_versions
    WHERE jurisdiction_id = NEW.jurisdiction_id
      AND language_id = NEW.language_id
      AND effective_from = NEW.effective_from
      AND record_kind_code = 'assertion'
  ) THEN RAISE(ABORT, 'effective point already has an initial assertion') END;

  SELECT CASE WHEN NEW.corrects_jurisdiction_version_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM atlas_jurisdiction_versions predecessor
    WHERE predecessor.id = NEW.corrects_jurisdiction_version_id
      AND predecessor.jurisdiction_id = NEW.jurisdiction_id
      AND predecessor.language_id = NEW.language_id
      AND predecessor.effective_from = NEW.effective_from
      AND predecessor.record_kind_code <> 'withdrawal'
      AND predecessor.recorded_at < NEW.recorded_at
      AND NOT EXISTS (
        SELECT 1 FROM atlas_jurisdiction_versions successor
        WHERE successor.corrects_jurisdiction_version_id = predecessor.id
      )
  ) THEN RAISE(ABORT, 'correction must target the current leaf at the same effective point and be recorded later') END;
END;

CREATE TRIGGER atlas_principals_immutable_update BEFORE UPDATE ON atlas_principals BEGIN SELECT RAISE(ABORT, 'principal identities are immutable'); END;
CREATE TRIGGER atlas_principals_immutable_delete BEFORE DELETE ON atlas_principals BEGIN SELECT RAISE(ABORT, 'principal identities are immutable'); END;
CREATE TRIGGER atlas_languages_immutable_update BEFORE UPDATE ON atlas_languages BEGIN SELECT RAISE(ABORT, 'language identities are immutable'); END;
CREATE TRIGGER atlas_languages_immutable_delete BEFORE DELETE ON atlas_languages BEGIN SELECT RAISE(ABORT, 'language identities are immutable'); END;
CREATE TRIGGER atlas_jurisdictions_immutable_update BEFORE UPDATE ON atlas_jurisdictions BEGIN SELECT RAISE(ABORT, 'jurisdiction identities are immutable'); END;
CREATE TRIGGER atlas_jurisdictions_immutable_delete BEFORE DELETE ON atlas_jurisdictions BEGIN SELECT RAISE(ABORT, 'jurisdiction identities are immutable'); END;
CREATE TRIGGER atlas_jurisdiction_versions_immutable_update BEFORE UPDATE ON atlas_jurisdiction_versions BEGIN SELECT RAISE(ABORT, 'jurisdiction versions are immutable'); END;
CREATE TRIGGER atlas_jurisdiction_versions_immutable_delete BEFORE DELETE ON atlas_jurisdiction_versions BEGIN SELECT RAISE(ABORT, 'jurisdiction versions are immutable'); END;
