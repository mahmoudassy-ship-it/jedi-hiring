PRAGMA foreign_keys = ON;

BEGIN IMMEDIATE;

CREATE TABLE atlas_principals (
  id INTEGER PRIMARY KEY,
  principal_code TEXT NOT NULL UNIQUE,
  principal_kind_code TEXT NOT NULL CHECK (principal_kind_code IN ('human', 'service')),
  display_name TEXT NOT NULL,
  external_subject TEXT UNIQUE,
  is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
  created_at TEXT NOT NULL,
  retired_at TEXT,
  CHECK (retired_at IS NULL OR retired_at > created_at)
);

CREATE TABLE atlas_review_roles (
  id INTEGER PRIMARY KEY,
  role_code TEXT NOT NULL UNIQUE,
  label TEXT NOT NULL,
  description TEXT NOT NULL,
  eligible_principal_kind_code TEXT NOT NULL CHECK (eligible_principal_kind_code IN ('human', 'service', 'either')),
  is_human_review_role INTEGER NOT NULL CHECK (is_human_review_role IN (0, 1)),
  is_publication_role INTEGER NOT NULL DEFAULT 0 CHECK (is_publication_role IN (0, 1)),
  is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
  CHECK (is_human_review_role = 0 OR eligible_principal_kind_code = 'human'),
  CHECK (is_publication_role = 0 OR (is_human_review_role = 1 AND eligible_principal_kind_code = 'human'))
);

CREATE TABLE atlas_principal_role_grants (
  id INTEGER PRIMARY KEY,
  principal_id INTEGER NOT NULL REFERENCES atlas_principals(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  review_role_id INTEGER NOT NULL REFERENCES atlas_review_roles(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  granted_by_principal_id INTEGER NOT NULL REFERENCES atlas_principals(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  valid_from TEXT NOT NULL,
  valid_to TEXT,
  granted_at TEXT NOT NULL,
  rationale TEXT NOT NULL,
  UNIQUE (principal_id, review_role_id, valid_from),
  CHECK (valid_to IS NULL OR valid_to > valid_from)
);

CREATE TABLE atlas_principal_role_revocations (
  id INTEGER PRIMARY KEY,
  principal_role_grant_id INTEGER NOT NULL REFERENCES atlas_principal_role_grants(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  revoked_by_principal_id INTEGER NOT NULL REFERENCES atlas_principals(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  revoked_on TEXT NOT NULL,
  recorded_at TEXT NOT NULL,
  reason TEXT NOT NULL,
  UNIQUE (principal_role_grant_id, revoked_on)
);

CREATE TABLE atlas_qualification_types (
  id INTEGER PRIMARY KEY,
  qualification_type_code TEXT NOT NULL UNIQUE,
  label TEXT NOT NULL,
  description TEXT NOT NULL,
  is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1))
);

CREATE TABLE atlas_taxonomy_types (
  id INTEGER PRIMARY KEY,
  taxonomy_type_code TEXT NOT NULL UNIQUE,
  label TEXT NOT NULL,
  description TEXT NOT NULL,
  is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1))
);

CREATE TABLE atlas_terms (
  id INTEGER PRIMARY KEY,
  taxonomy_type_id INTEGER NOT NULL REFERENCES atlas_taxonomy_types(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  term_code TEXT NOT NULL,
  is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
  created_at TEXT NOT NULL,
  UNIQUE (taxonomy_type_id, term_code)
);

CREATE TABLE atlas_term_versions (
  id INTEGER PRIMARY KEY,
  term_id INTEGER NOT NULL REFERENCES atlas_terms(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  label TEXT NOT NULL,
  definition TEXT NOT NULL,
  valid_from TEXT NOT NULL,
  valid_to TEXT,
  content_hash TEXT NOT NULL CHECK (length(content_hash) = 64),
  created_at TEXT NOT NULL,
  created_by_principal_id INTEGER REFERENCES atlas_principals(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  UNIQUE (term_id, valid_from),
  CHECK (valid_to IS NULL OR valid_to > valid_from)
);

CREATE TABLE atlas_languages (
  term_id INTEGER PRIMARY KEY REFERENCES atlas_terms(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  bcp47_code TEXT NOT NULL UNIQUE,
  CHECK (length(bcp47_code) BETWEEN 2 AND 35)
);

CREATE TABLE atlas_hiring_stages (
  term_id INTEGER PRIMARY KEY REFERENCES atlas_terms(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  display_order INTEGER NOT NULL UNIQUE CHECK (display_order > 0)
);

CREATE TABLE atlas_legal_lenses (
  term_id INTEGER PRIMARY KEY REFERENCES atlas_terms(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  display_order INTEGER NOT NULL UNIQUE CHECK (display_order > 0)
);

CREATE TABLE atlas_actor_types (
  term_id INTEGER PRIMARY KEY REFERENCES atlas_terms(id) ON UPDATE RESTRICT ON DELETE RESTRICT
);

CREATE TABLE atlas_normative_roles (
  term_id INTEGER PRIMARY KEY REFERENCES atlas_terms(id) ON UPDATE RESTRICT ON DELETE RESTRICT
);

CREATE TABLE atlas_protected_grounds (
  term_id INTEGER PRIMARY KEY REFERENCES atlas_terms(id) ON UPDATE RESTRICT ON DELETE RESTRICT
);

CREATE TABLE atlas_data_categories (
  term_id INTEGER PRIMARY KEY REFERENCES atlas_terms(id) ON UPDATE RESTRICT ON DELETE RESTRICT
);

CREATE TABLE atlas_lifecycle_states (
  term_id INTEGER PRIMARY KEY REFERENCES atlas_terms(id) ON UPDATE RESTRICT ON DELETE RESTRICT
);

CREATE TABLE atlas_subject_areas (
  term_id INTEGER PRIMARY KEY REFERENCES atlas_terms(id) ON UPDATE RESTRICT ON DELETE RESTRICT
);

CREATE TABLE atlas_term_labels (
  id INTEGER PRIMARY KEY,
  term_version_id INTEGER NOT NULL REFERENCES atlas_term_versions(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  language_id INTEGER NOT NULL REFERENCES atlas_languages(term_id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  label TEXT NOT NULL,
  is_preferred INTEGER NOT NULL DEFAULT 1 CHECK (is_preferred IN (0, 1)),
  UNIQUE (term_version_id, language_id, label)
);

CREATE TABLE atlas_term_aliases (
  id INTEGER PRIMARY KEY,
  term_id INTEGER NOT NULL REFERENCES atlas_terms(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  language_id INTEGER NOT NULL REFERENCES atlas_languages(term_id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  alias TEXT NOT NULL,
  valid_from TEXT NOT NULL,
  valid_to TEXT,
  UNIQUE (term_id, language_id, alias, valid_from),
  CHECK (valid_to IS NULL OR valid_to > valid_from)
);

CREATE TABLE atlas_term_replacements (
  id INTEGER PRIMARY KEY,
  replaced_term_id INTEGER NOT NULL REFERENCES atlas_terms(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  replacement_term_id INTEGER NOT NULL REFERENCES atlas_terms(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  valid_from TEXT NOT NULL,
  reason TEXT NOT NULL,
  UNIQUE (replaced_term_id, replacement_term_id, valid_from),
  CHECK (replaced_term_id <> replacement_term_id)
);

CREATE TABLE atlas_term_change_events (
  id INTEGER PRIMARY KEY,
  term_id INTEGER NOT NULL REFERENCES atlas_terms(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  changed_by_principal_id INTEGER REFERENCES atlas_principals(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  change_kind_code TEXT NOT NULL CHECK (change_kind_code IN ('created', 'versioned', 'deprecated', 'replaced', 'reactivated')),
  previous_term_version_id INTEGER REFERENCES atlas_term_versions(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  resulting_term_version_id INTEGER REFERENCES atlas_term_versions(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  changed_at TEXT NOT NULL,
  reason TEXT NOT NULL
);

CREATE TABLE atlas_jurisdictions (
  id INTEGER PRIMARY KEY,
  jurisdiction_code TEXT NOT NULL UNIQUE,
  jurisdiction_kind_code TEXT NOT NULL CHECK (jurisdiction_kind_code IN ('supranational', 'state', 'regional', 'devolved', 'local')),
  is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
  created_at TEXT NOT NULL
);

CREATE TABLE atlas_jurisdiction_versions (
  id INTEGER PRIMARY KEY,
  jurisdiction_id INTEGER NOT NULL REFERENCES atlas_jurisdictions(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  name TEXT NOT NULL,
  description TEXT,
  valid_from TEXT NOT NULL,
  valid_to TEXT,
  content_hash TEXT NOT NULL CHECK (length(content_hash) = 64),
  created_at TEXT NOT NULL,
  created_by_principal_id INTEGER REFERENCES atlas_principals(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  UNIQUE (jurisdiction_id, valid_from),
  CHECK (valid_to IS NULL OR valid_to > valid_from)
);

CREATE TABLE atlas_jurisdiction_containments (
  id INTEGER PRIMARY KEY,
  parent_jurisdiction_id INTEGER NOT NULL REFERENCES atlas_jurisdictions(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  child_jurisdiction_id INTEGER NOT NULL REFERENCES atlas_jurisdictions(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  valid_from TEXT NOT NULL,
  valid_to TEXT,
  recorded_at TEXT NOT NULL,
  UNIQUE (parent_jurisdiction_id, child_jurisdiction_id, valid_from),
  CHECK (parent_jurisdiction_id <> child_jurisdiction_id),
  CHECK (valid_to IS NULL OR valid_to > valid_from)
);

CREATE TABLE atlas_membership_types (
  id INTEGER PRIMARY KEY,
  membership_type_code TEXT NOT NULL UNIQUE,
  label TEXT NOT NULL,
  description TEXT NOT NULL,
  is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1))
);

CREATE TABLE atlas_jurisdiction_memberships (
  id INTEGER PRIMARY KEY,
  member_jurisdiction_id INTEGER NOT NULL REFERENCES atlas_jurisdictions(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  organization_jurisdiction_id INTEGER NOT NULL REFERENCES atlas_jurisdictions(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  membership_type_id INTEGER NOT NULL REFERENCES atlas_membership_types(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  valid_from TEXT NOT NULL,
  valid_to TEXT,
  recorded_at TEXT NOT NULL,
  UNIQUE (member_jurisdiction_id, organization_jurisdiction_id, membership_type_id, valid_from),
  CHECK (member_jurisdiction_id <> organization_jurisdiction_id),
  CHECK (valid_to IS NULL OR valid_to > valid_from)
);

CREATE TABLE atlas_coverage_scopes (
  id INTEGER PRIMARY KEY,
  coverage_scope_code TEXT NOT NULL UNIQUE,
  coverage_scope_kind_code TEXT NOT NULL CHECK (coverage_scope_kind_code IN ('sector', 'employer_size', 'employer_type', 'collective_agreement', 'personal')),
  is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
  created_at TEXT NOT NULL
);

CREATE TABLE atlas_coverage_scope_versions (
  id INTEGER PRIMARY KEY,
  coverage_scope_id INTEGER NOT NULL REFERENCES atlas_coverage_scopes(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  label TEXT NOT NULL,
  definition TEXT NOT NULL,
  valid_from TEXT NOT NULL,
  valid_to TEXT,
  content_hash TEXT NOT NULL CHECK (length(content_hash) = 64),
  created_at TEXT NOT NULL,
  created_by_principal_id INTEGER REFERENCES atlas_principals(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  UNIQUE (coverage_scope_id, valid_from),
  CHECK (valid_to IS NULL OR valid_to > valid_from)
);

CREATE TABLE atlas_sector_scopes (coverage_scope_id INTEGER PRIMARY KEY REFERENCES atlas_coverage_scopes(id) ON UPDATE RESTRICT ON DELETE RESTRICT);
CREATE TABLE atlas_employer_size_scopes (coverage_scope_id INTEGER PRIMARY KEY REFERENCES atlas_coverage_scopes(id) ON UPDATE RESTRICT ON DELETE RESTRICT, minimum_workers INTEGER, maximum_workers INTEGER, CHECK (minimum_workers IS NULL OR minimum_workers >= 0), CHECK (maximum_workers IS NULL OR maximum_workers >= 0), CHECK (minimum_workers IS NULL OR maximum_workers IS NULL OR maximum_workers >= minimum_workers));
CREATE TABLE atlas_employer_type_scopes (coverage_scope_id INTEGER PRIMARY KEY REFERENCES atlas_coverage_scopes(id) ON UPDATE RESTRICT ON DELETE RESTRICT);
CREATE TABLE atlas_collective_agreement_scopes (coverage_scope_id INTEGER PRIMARY KEY REFERENCES atlas_coverage_scopes(id) ON UPDATE RESTRICT ON DELETE RESTRICT);
CREATE TABLE atlas_personal_scopes (coverage_scope_id INTEGER PRIMARY KEY REFERENCES atlas_coverage_scopes(id) ON UPDATE RESTRICT ON DELETE RESTRICT);

CREATE TABLE atlas_qualification_assertions (
  id INTEGER PRIMARY KEY,
  principal_id INTEGER NOT NULL REFERENCES atlas_principals(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  qualification_type_id INTEGER NOT NULL REFERENCES atlas_qualification_types(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  asserted_by_principal_id INTEGER NOT NULL REFERENCES atlas_principals(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  verified_by_principal_id INTEGER REFERENCES atlas_principals(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  assertion_status_code TEXT NOT NULL CHECK (assertion_status_code IN ('asserted', 'verified', 'rejected')),
  valid_from TEXT NOT NULL,
  valid_to TEXT,
  asserted_at TEXT NOT NULL,
  verified_at TEXT,
  supersedes_qualification_assertion_id INTEGER REFERENCES atlas_qualification_assertions(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  evidence_reference TEXT,
  CHECK (valid_to IS NULL OR valid_to > valid_from),
  CHECK ((assertion_status_code = 'verified') = (verified_by_principal_id IS NOT NULL AND verified_at IS NOT NULL)),
  CHECK (supersedes_qualification_assertion_id IS NULL OR supersedes_qualification_assertion_id <> id)
);

CREATE TABLE atlas_qualification_revocations (
  id INTEGER PRIMARY KEY,
  qualification_assertion_id INTEGER NOT NULL REFERENCES atlas_qualification_assertions(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  revoked_by_principal_id INTEGER NOT NULL REFERENCES atlas_principals(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  revoked_on TEXT NOT NULL,
  recorded_at TEXT NOT NULL,
  reason TEXT NOT NULL,
  UNIQUE (qualification_assertion_id, revoked_on)
);

CREATE TABLE atlas_qualification_jurisdictions (qualification_assertion_id INTEGER NOT NULL REFERENCES atlas_qualification_assertions(id) ON UPDATE RESTRICT ON DELETE RESTRICT, jurisdiction_id INTEGER NOT NULL REFERENCES atlas_jurisdictions(id) ON UPDATE RESTRICT ON DELETE RESTRICT, PRIMARY KEY (qualification_assertion_id, jurisdiction_id));
CREATE TABLE atlas_qualification_coverage_scopes (qualification_assertion_id INTEGER NOT NULL REFERENCES atlas_qualification_assertions(id) ON UPDATE RESTRICT ON DELETE RESTRICT, coverage_scope_id INTEGER NOT NULL REFERENCES atlas_coverage_scopes(id) ON UPDATE RESTRICT ON DELETE RESTRICT, PRIMARY KEY (qualification_assertion_id, coverage_scope_id));
CREATE TABLE atlas_qualification_subject_areas (qualification_assertion_id INTEGER NOT NULL REFERENCES atlas_qualification_assertions(id) ON UPDATE RESTRICT ON DELETE RESTRICT, subject_area_id INTEGER NOT NULL REFERENCES atlas_subject_areas(term_id) ON UPDATE RESTRICT ON DELETE RESTRICT, PRIMARY KEY (qualification_assertion_id, subject_area_id));
CREATE TABLE atlas_qualification_languages (qualification_assertion_id INTEGER NOT NULL REFERENCES atlas_qualification_assertions(id) ON UPDATE RESTRICT ON DELETE RESTRICT, language_id INTEGER NOT NULL REFERENCES atlas_languages(term_id) ON UPDATE RESTRICT ON DELETE RESTRICT, PRIMARY KEY (qualification_assertion_id, language_id));

CREATE TABLE atlas_review_policies (
  id INTEGER PRIMARY KEY,
  policy_code TEXT NOT NULL UNIQUE,
  transition_code TEXT NOT NULL UNIQUE CHECK (transition_code IN ('candidate_to_draft', 'proposition_to_public')),
  label TEXT NOT NULL,
  description TEXT NOT NULL,
  is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
  created_at TEXT NOT NULL
);

CREATE TABLE atlas_review_policy_versions (
  id INTEGER PRIMARY KEY,
  review_policy_id INTEGER NOT NULL REFERENCES atlas_review_policies(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  version_number INTEGER NOT NULL CHECK (version_number > 0),
  valid_from TEXT NOT NULL,
  valid_to TEXT,
  content_hash TEXT NOT NULL CHECK (length(content_hash) = 64),
  created_at TEXT NOT NULL,
  created_by_principal_id INTEGER REFERENCES atlas_principals(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  UNIQUE (review_policy_id, version_number),
  UNIQUE (review_policy_id, valid_from),
  CHECK (valid_to IS NULL OR valid_to > valid_from)
);

CREATE TABLE atlas_review_policy_version_seals (
  review_policy_version_id INTEGER PRIMARY KEY REFERENCES atlas_review_policy_versions(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  sealed_at TEXT NOT NULL,
  sealed_by_principal_id INTEGER REFERENCES atlas_principals(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  canonical_payload_hash TEXT NOT NULL CHECK (length(canonical_payload_hash) = 64)
);

CREATE TABLE atlas_review_gates (
  id INTEGER PRIMARY KEY,
  gate_code TEXT NOT NULL UNIQUE,
  label TEXT NOT NULL,
  description TEXT NOT NULL,
  is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1))
);

CREATE TABLE atlas_review_policy_requirements (
  id INTEGER PRIMARY KEY,
  review_policy_version_id INTEGER NOT NULL REFERENCES atlas_review_policy_versions(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  review_gate_id INTEGER NOT NULL REFERENCES atlas_review_gates(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  review_role_id INTEGER NOT NULL REFERENCES atlas_review_roles(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  qualification_type_id INTEGER REFERENCES atlas_qualification_types(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  condition_code TEXT NOT NULL CHECK (condition_code IN ('always', 'national_material', 'non_authoritative_translation')),
  minimum_approvals INTEGER NOT NULL CHECK (minimum_approvals > 0),
  is_human_only INTEGER NOT NULL CHECK (is_human_only IN (0, 1)),
  is_qualification_required INTEGER NOT NULL CHECK (is_qualification_required IN (0, 1)),
  is_jurisdiction_match_required INTEGER NOT NULL CHECK (is_jurisdiction_match_required IN (0, 1)),
  maximum_review_age_days INTEGER CHECK (maximum_review_age_days > 0),
  sequence_number INTEGER NOT NULL CHECK (sequence_number > 0),
  is_non_waivable INTEGER NOT NULL DEFAULT 1 CHECK (is_non_waivable IN (0, 1)),
  UNIQUE (review_policy_version_id, review_gate_id),
  UNIQUE (review_policy_version_id, sequence_number),
  CHECK (is_qualification_required = 0 OR qualification_type_id IS NOT NULL),
  CHECK (is_jurisdiction_match_required = 0 OR is_qualification_required = 1)
);

CREATE TABLE atlas_review_policy_separation_rules (
  id INTEGER PRIMARY KEY,
  review_policy_version_id INTEGER NOT NULL REFERENCES atlas_review_policy_versions(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  left_review_role_id INTEGER NOT NULL REFERENCES atlas_review_roles(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  right_review_role_id INTEGER NOT NULL REFERENCES atlas_review_roles(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  rule_code TEXT NOT NULL CHECK (rule_code = 'different_principal'),
  is_non_waivable INTEGER NOT NULL DEFAULT 1 CHECK (is_non_waivable = 1),
  UNIQUE (review_policy_version_id, left_review_role_id, right_review_role_id),
  CHECK (left_review_role_id < right_review_role_id)
);

CREATE INDEX atlas_principal_role_grants_as_of_idx ON atlas_principal_role_grants(principal_id, review_role_id, valid_from, valid_to);
CREATE INDEX atlas_principal_role_revocations_as_of_idx ON atlas_principal_role_revocations(principal_role_grant_id, revoked_on);
CREATE INDEX atlas_qualification_assertions_as_of_idx ON atlas_qualification_assertions(principal_id, qualification_type_id, valid_from, valid_to);
CREATE INDEX atlas_qualification_revocations_as_of_idx ON atlas_qualification_revocations(qualification_assertion_id, revoked_on);
CREATE INDEX atlas_terms_type_code_idx ON atlas_terms(taxonomy_type_id, term_code);
CREATE INDEX atlas_term_versions_as_of_idx ON atlas_term_versions(term_id, valid_from, valid_to);
CREATE INDEX atlas_term_aliases_lookup_idx ON atlas_term_aliases(language_id, alias, valid_from, valid_to);
CREATE INDEX atlas_term_change_events_term_at_idx ON atlas_term_change_events(term_id, changed_at);
CREATE INDEX atlas_jurisdiction_versions_as_of_idx ON atlas_jurisdiction_versions(jurisdiction_id, valid_from, valid_to);
CREATE INDEX atlas_jurisdiction_containments_child_as_of_idx ON atlas_jurisdiction_containments(child_jurisdiction_id, valid_from, valid_to);
CREATE INDEX atlas_jurisdiction_containments_parent_as_of_idx ON atlas_jurisdiction_containments(parent_jurisdiction_id, valid_from, valid_to);
CREATE INDEX atlas_jurisdiction_memberships_member_as_of_idx ON atlas_jurisdiction_memberships(member_jurisdiction_id, membership_type_id, valid_from, valid_to);
CREATE INDEX atlas_jurisdiction_memberships_organization_as_of_idx ON atlas_jurisdiction_memberships(organization_jurisdiction_id, membership_type_id, valid_from, valid_to);
CREATE INDEX atlas_coverage_scope_versions_as_of_idx ON atlas_coverage_scope_versions(coverage_scope_id, valid_from, valid_to);
CREATE INDEX atlas_review_policy_versions_as_of_idx ON atlas_review_policy_versions(review_policy_id, valid_from, valid_to);
CREATE INDEX atlas_review_policy_requirements_policy_idx ON atlas_review_policy_requirements(review_policy_version_id, sequence_number);

CREATE TRIGGER atlas_jurisdiction_containments_prevent_cycles_insert
BEFORE INSERT ON atlas_jurisdiction_containments
BEGIN
  SELECT CASE WHEN NEW.parent_jurisdiction_id = NEW.child_jurisdiction_id THEN RAISE(ABORT, 'jurisdiction containment self-cycle') END;
  SELECT CASE WHEN EXISTS (
    WITH RECURSIVE ancestors(id) AS (
      SELECT parent_jurisdiction_id FROM atlas_jurisdiction_containments
      WHERE child_jurisdiction_id = NEW.parent_jurisdiction_id
        AND valid_from < COALESCE(NEW.valid_to, '9999-12-31') AND NEW.valid_from < COALESCE(valid_to, '9999-12-31')
      UNION
      SELECT c.parent_jurisdiction_id FROM atlas_jurisdiction_containments c JOIN ancestors a ON c.child_jurisdiction_id = a.id
      WHERE c.valid_from < COALESCE(NEW.valid_to, '9999-12-31') AND NEW.valid_from < COALESCE(c.valid_to, '9999-12-31')
    ) SELECT 1 FROM ancestors WHERE id = NEW.child_jurisdiction_id
  ) THEN RAISE(ABORT, 'jurisdiction containment cycle') END;
END;

CREATE TRIGGER atlas_jurisdiction_containments_prevent_overlap_insert
BEFORE INSERT ON atlas_jurisdiction_containments
WHEN EXISTS (SELECT 1 FROM atlas_jurisdiction_containments e WHERE e.child_jurisdiction_id = NEW.child_jurisdiction_id AND e.valid_from < COALESCE(NEW.valid_to, '9999-12-31') AND NEW.valid_from < COALESCE(e.valid_to, '9999-12-31'))
BEGIN SELECT RAISE(ABORT, 'overlapping jurisdiction containment'); END;

CREATE TRIGGER atlas_jurisdiction_memberships_prevent_overlap_insert
BEFORE INSERT ON atlas_jurisdiction_memberships
WHEN EXISTS (SELECT 1 FROM atlas_jurisdiction_memberships e WHERE e.member_jurisdiction_id = NEW.member_jurisdiction_id AND e.organization_jurisdiction_id = NEW.organization_jurisdiction_id AND e.membership_type_id = NEW.membership_type_id AND e.valid_from < COALESCE(NEW.valid_to, '9999-12-31') AND NEW.valid_from < COALESCE(e.valid_to, '9999-12-31'))
BEGIN SELECT RAISE(ABORT, 'overlapping jurisdiction membership'); END;

CREATE TRIGGER atlas_principal_role_grants_prevent_overlap_insert
BEFORE INSERT ON atlas_principal_role_grants
WHEN EXISTS (SELECT 1 FROM atlas_principal_role_grants e WHERE e.principal_id = NEW.principal_id AND e.review_role_id = NEW.review_role_id AND e.valid_from < COALESCE(NEW.valid_to, '9999-12-31') AND NEW.valid_from < COALESCE(e.valid_to, '9999-12-31'))
BEGIN SELECT RAISE(ABORT, 'overlapping principal role grant'); END;

CREATE TRIGGER atlas_term_versions_prevent_overlap_insert BEFORE INSERT ON atlas_term_versions
WHEN EXISTS (SELECT 1 FROM atlas_term_versions e WHERE e.term_id = NEW.term_id AND e.valid_from < COALESCE(NEW.valid_to, '9999-12-31') AND NEW.valid_from < COALESCE(e.valid_to, '9999-12-31'))
BEGIN SELECT RAISE(ABORT, 'overlapping term version'); END;

CREATE TRIGGER atlas_jurisdiction_versions_prevent_overlap_insert BEFORE INSERT ON atlas_jurisdiction_versions
WHEN EXISTS (SELECT 1 FROM atlas_jurisdiction_versions e WHERE e.jurisdiction_id = NEW.jurisdiction_id AND e.valid_from < COALESCE(NEW.valid_to, '9999-12-31') AND NEW.valid_from < COALESCE(e.valid_to, '9999-12-31'))
BEGIN SELECT RAISE(ABORT, 'overlapping jurisdiction version'); END;

CREATE TRIGGER atlas_coverage_scope_versions_prevent_overlap_insert BEFORE INSERT ON atlas_coverage_scope_versions
WHEN EXISTS (SELECT 1 FROM atlas_coverage_scope_versions e WHERE e.coverage_scope_id = NEW.coverage_scope_id AND e.valid_from < COALESCE(NEW.valid_to, '9999-12-31') AND NEW.valid_from < COALESCE(e.valid_to, '9999-12-31'))
BEGIN SELECT RAISE(ABORT, 'overlapping coverage scope version'); END;

CREATE TRIGGER atlas_review_policy_requirements_validate_human_insert
BEFORE INSERT ON atlas_review_policy_requirements
WHEN NEW.is_human_only <> 1 OR EXISTS (SELECT 1 FROM atlas_review_roles r WHERE r.id = NEW.review_role_id AND r.eligible_principal_kind_code <> 'human')
BEGIN SELECT RAISE(ABORT, 'review and publication gates require human principals'); END;

CREATE TRIGGER atlas_review_policy_requirements_reject_sealed_insert BEFORE INSERT ON atlas_review_policy_requirements
WHEN EXISTS (SELECT 1 FROM atlas_review_policy_version_seals WHERE review_policy_version_id=NEW.review_policy_version_id)
BEGIN SELECT RAISE(ABORT, 'review policy version is sealed'); END;

CREATE TRIGGER atlas_review_policy_separation_rules_reject_sealed_insert BEFORE INSERT ON atlas_review_policy_separation_rules
WHEN EXISTS (SELECT 1 FROM atlas_review_policy_version_seals WHERE review_policy_version_id=NEW.review_policy_version_id)
BEGIN SELECT RAISE(ABORT, 'review policy version is sealed'); END;

CREATE TRIGGER atlas_role_grants_validate_principal_kind_insert
BEFORE INSERT ON atlas_principal_role_grants
WHEN EXISTS (SELECT 1 FROM atlas_principals p JOIN atlas_review_roles r ON r.id = NEW.review_role_id WHERE p.id = NEW.principal_id AND r.eligible_principal_kind_code <> 'either' AND r.eligible_principal_kind_code <> p.principal_kind_code)
BEGIN SELECT RAISE(ABORT, 'principal kind is not eligible for review role'); END;

CREATE TRIGGER atlas_qualification_assertions_validate_humans_insert
BEFORE INSERT ON atlas_qualification_assertions
WHEN EXISTS (SELECT 1 FROM atlas_principals WHERE id = NEW.principal_id AND principal_kind_code <> 'human')
  OR (NEW.verified_by_principal_id IS NOT NULL AND EXISTS (SELECT 1 FROM atlas_principals WHERE id = NEW.verified_by_principal_id AND principal_kind_code <> 'human'))
BEGIN SELECT RAISE(ABORT, 'review qualifications require human principals'); END;

CREATE TRIGGER atlas_role_revocations_validate_date_insert BEFORE INSERT ON atlas_principal_role_revocations
WHEN NEW.revoked_on < (SELECT valid_from FROM atlas_principal_role_grants WHERE id=NEW.principal_role_grant_id)
BEGIN SELECT RAISE(ABORT, 'revocation predates role grant'); END;

CREATE TRIGGER atlas_qualification_revocations_validate_date_insert BEFORE INSERT ON atlas_qualification_revocations
WHEN NEW.revoked_on < (SELECT valid_from FROM atlas_qualification_assertions WHERE id=NEW.qualification_assertion_id)
BEGIN SELECT RAISE(ABORT, 'revocation predates qualification'); END;

CREATE TRIGGER atlas_coverage_scopes_validate_sector BEFORE INSERT ON atlas_sector_scopes WHEN (SELECT coverage_scope_kind_code FROM atlas_coverage_scopes WHERE id=NEW.coverage_scope_id) <> 'sector' BEGIN SELECT RAISE(ABORT, 'wrong coverage subtype'); END;
CREATE TRIGGER atlas_coverage_scopes_validate_employer_size BEFORE INSERT ON atlas_employer_size_scopes WHEN (SELECT coverage_scope_kind_code FROM atlas_coverage_scopes WHERE id=NEW.coverage_scope_id) <> 'employer_size' BEGIN SELECT RAISE(ABORT, 'wrong coverage subtype'); END;
CREATE TRIGGER atlas_coverage_scopes_validate_employer_type BEFORE INSERT ON atlas_employer_type_scopes WHEN (SELECT coverage_scope_kind_code FROM atlas_coverage_scopes WHERE id=NEW.coverage_scope_id) <> 'employer_type' BEGIN SELECT RAISE(ABORT, 'wrong coverage subtype'); END;
CREATE TRIGGER atlas_coverage_scopes_validate_collective_agreement BEFORE INSERT ON atlas_collective_agreement_scopes WHEN (SELECT coverage_scope_kind_code FROM atlas_coverage_scopes WHERE id=NEW.coverage_scope_id) <> 'collective_agreement' BEGIN SELECT RAISE(ABORT, 'wrong coverage subtype'); END;
CREATE TRIGGER atlas_coverage_scopes_validate_personal BEFORE INSERT ON atlas_personal_scopes WHEN (SELECT coverage_scope_kind_code FROM atlas_coverage_scopes WHERE id=NEW.coverage_scope_id) <> 'personal' BEGIN SELECT RAISE(ABORT, 'wrong coverage subtype'); END;

CREATE TRIGGER atlas_terms_validate_subtype_hiring_stage BEFORE INSERT ON atlas_hiring_stages WHEN (SELECT taxonomy_type_code FROM atlas_terms t JOIN atlas_taxonomy_types y ON y.id=t.taxonomy_type_id WHERE t.id=NEW.term_id) <> 'hiring_stage' BEGIN SELECT RAISE(ABORT, 'wrong taxonomy subtype'); END;
CREATE TRIGGER atlas_terms_validate_subtype_legal_lens BEFORE INSERT ON atlas_legal_lenses WHEN (SELECT taxonomy_type_code FROM atlas_terms t JOIN atlas_taxonomy_types y ON y.id=t.taxonomy_type_id WHERE t.id=NEW.term_id) <> 'legal_lens' BEGIN SELECT RAISE(ABORT, 'wrong taxonomy subtype'); END;
CREATE TRIGGER atlas_terms_validate_subtype_actor_type BEFORE INSERT ON atlas_actor_types WHEN (SELECT taxonomy_type_code FROM atlas_terms t JOIN atlas_taxonomy_types y ON y.id=t.taxonomy_type_id WHERE t.id=NEW.term_id) <> 'actor_type' BEGIN SELECT RAISE(ABORT, 'wrong taxonomy subtype'); END;
CREATE TRIGGER atlas_terms_validate_subtype_normative_role BEFORE INSERT ON atlas_normative_roles WHEN (SELECT taxonomy_type_code FROM atlas_terms t JOIN atlas_taxonomy_types y ON y.id=t.taxonomy_type_id WHERE t.id=NEW.term_id) <> 'normative_role' BEGIN SELECT RAISE(ABORT, 'wrong taxonomy subtype'); END;
CREATE TRIGGER atlas_terms_validate_subtype_protected_ground BEFORE INSERT ON atlas_protected_grounds WHEN (SELECT taxonomy_type_code FROM atlas_terms t JOIN atlas_taxonomy_types y ON y.id=t.taxonomy_type_id WHERE t.id=NEW.term_id) <> 'protected_ground' BEGIN SELECT RAISE(ABORT, 'wrong taxonomy subtype'); END;
CREATE TRIGGER atlas_terms_validate_subtype_data_category BEFORE INSERT ON atlas_data_categories WHEN (SELECT taxonomy_type_code FROM atlas_terms t JOIN atlas_taxonomy_types y ON y.id=t.taxonomy_type_id WHERE t.id=NEW.term_id) <> 'data_category' BEGIN SELECT RAISE(ABORT, 'wrong taxonomy subtype'); END;
CREATE TRIGGER atlas_terms_validate_subtype_language BEFORE INSERT ON atlas_languages WHEN (SELECT taxonomy_type_code FROM atlas_terms t JOIN atlas_taxonomy_types y ON y.id=t.taxonomy_type_id WHERE t.id=NEW.term_id) <> 'language' BEGIN SELECT RAISE(ABORT, 'wrong taxonomy subtype'); END;
CREATE TRIGGER atlas_terms_validate_subtype_lifecycle_state BEFORE INSERT ON atlas_lifecycle_states WHEN (SELECT taxonomy_type_code FROM atlas_terms t JOIN atlas_taxonomy_types y ON y.id=t.taxonomy_type_id WHERE t.id=NEW.term_id) <> 'lifecycle_state' BEGIN SELECT RAISE(ABORT, 'wrong taxonomy subtype'); END;
CREATE TRIGGER atlas_terms_validate_subtype_subject_area BEFORE INSERT ON atlas_subject_areas WHEN (SELECT taxonomy_type_code FROM atlas_terms t JOIN atlas_taxonomy_types y ON y.id=t.taxonomy_type_id WHERE t.id=NEW.term_id) <> 'subject_area' BEGIN SELECT RAISE(ABORT, 'wrong taxonomy subtype'); END;

CREATE TRIGGER atlas_term_versions_immutable_update BEFORE UPDATE ON atlas_term_versions BEGIN SELECT RAISE(ABORT, 'term versions are immutable'); END;
CREATE TRIGGER atlas_term_versions_immutable_delete BEFORE DELETE ON atlas_term_versions BEGIN SELECT RAISE(ABORT, 'term versions are immutable'); END;
CREATE TRIGGER atlas_jurisdiction_versions_immutable_update BEFORE UPDATE ON atlas_jurisdiction_versions BEGIN SELECT RAISE(ABORT, 'jurisdiction versions are immutable'); END;
CREATE TRIGGER atlas_jurisdiction_versions_immutable_delete BEFORE DELETE ON atlas_jurisdiction_versions BEGIN SELECT RAISE(ABORT, 'jurisdiction versions are immutable'); END;
CREATE TRIGGER atlas_coverage_scope_versions_immutable_update BEFORE UPDATE ON atlas_coverage_scope_versions BEGIN SELECT RAISE(ABORT, 'coverage scope versions are immutable'); END;
CREATE TRIGGER atlas_coverage_scope_versions_immutable_delete BEFORE DELETE ON atlas_coverage_scope_versions BEGIN SELECT RAISE(ABORT, 'coverage scope versions are immutable'); END;
CREATE TRIGGER atlas_review_policy_versions_immutable_update BEFORE UPDATE ON atlas_review_policy_versions BEGIN SELECT RAISE(ABORT, 'review policy versions are immutable'); END;
CREATE TRIGGER atlas_review_policy_versions_immutable_delete BEFORE DELETE ON atlas_review_policy_versions BEGIN SELECT RAISE(ABORT, 'review policy versions are immutable'); END;
CREATE TRIGGER atlas_role_grants_immutable_update BEFORE UPDATE ON atlas_principal_role_grants BEGIN SELECT RAISE(ABORT, 'role grants are immutable'); END;
CREATE TRIGGER atlas_role_grants_immutable_delete BEFORE DELETE ON atlas_principal_role_grants BEGIN SELECT RAISE(ABORT, 'role grants are immutable'); END;
CREATE TRIGGER atlas_role_revocations_append_only_update BEFORE UPDATE ON atlas_principal_role_revocations BEGIN SELECT RAISE(ABORT, 'role revocations are append-only'); END;
CREATE TRIGGER atlas_role_revocations_append_only_delete BEFORE DELETE ON atlas_principal_role_revocations BEGIN SELECT RAISE(ABORT, 'role revocations are append-only'); END;
CREATE TRIGGER atlas_qualification_assertions_immutable_update BEFORE UPDATE ON atlas_qualification_assertions BEGIN SELECT RAISE(ABORT, 'qualification assertions are immutable'); END;
CREATE TRIGGER atlas_qualification_assertions_immutable_delete BEFORE DELETE ON atlas_qualification_assertions BEGIN SELECT RAISE(ABORT, 'qualification assertions are immutable'); END;
CREATE TRIGGER atlas_qualification_revocations_append_only_update BEFORE UPDATE ON atlas_qualification_revocations BEGIN SELECT RAISE(ABORT, 'qualification revocations are append-only'); END;
CREATE TRIGGER atlas_qualification_revocations_append_only_delete BEFORE DELETE ON atlas_qualification_revocations BEGIN SELECT RAISE(ABORT, 'qualification revocations are append-only'); END;
CREATE TRIGGER atlas_term_change_events_append_only_update BEFORE UPDATE ON atlas_term_change_events BEGIN SELECT RAISE(ABORT, 'term change events are append-only'); END;
CREATE TRIGGER atlas_term_change_events_append_only_delete BEFORE DELETE ON atlas_term_change_events BEGIN SELECT RAISE(ABORT, 'term change events are append-only'); END;
CREATE TRIGGER atlas_jurisdiction_containments_immutable_update BEFORE UPDATE ON atlas_jurisdiction_containments BEGIN SELECT RAISE(ABORT, 'jurisdiction containments are immutable'); END;
CREATE TRIGGER atlas_jurisdiction_containments_immutable_delete BEFORE DELETE ON atlas_jurisdiction_containments BEGIN SELECT RAISE(ABORT, 'jurisdiction containments are immutable'); END;
CREATE TRIGGER atlas_jurisdiction_memberships_immutable_update BEFORE UPDATE ON atlas_jurisdiction_memberships BEGIN SELECT RAISE(ABORT, 'jurisdiction memberships are immutable'); END;
CREATE TRIGGER atlas_jurisdiction_memberships_immutable_delete BEFORE DELETE ON atlas_jurisdiction_memberships BEGIN SELECT RAISE(ABORT, 'jurisdiction memberships are immutable'); END;
CREATE TRIGGER atlas_review_policy_requirements_immutable_update BEFORE UPDATE ON atlas_review_policy_requirements BEGIN SELECT RAISE(ABORT, 'review policy requirements are immutable'); END;
CREATE TRIGGER atlas_review_policy_requirements_immutable_delete BEFORE DELETE ON atlas_review_policy_requirements BEGIN SELECT RAISE(ABORT, 'review policy requirements are immutable'); END;
CREATE TRIGGER atlas_review_policy_separation_rules_immutable_update BEFORE UPDATE ON atlas_review_policy_separation_rules BEGIN SELECT RAISE(ABORT, 'review policy separation rules are immutable'); END;
CREATE TRIGGER atlas_review_policy_separation_rules_immutable_delete BEFORE DELETE ON atlas_review_policy_separation_rules BEGIN SELECT RAISE(ABORT, 'review policy separation rules are immutable'); END;
CREATE TRIGGER atlas_review_policy_version_seals_append_only_update BEFORE UPDATE ON atlas_review_policy_version_seals BEGIN SELECT RAISE(ABORT, 'review policy version seals are append-only'); END;
CREATE TRIGGER atlas_review_policy_version_seals_append_only_delete BEFORE DELETE ON atlas_review_policy_version_seals BEGIN SELECT RAISE(ABORT, 'review policy version seals are append-only'); END;

INSERT INTO atlas_review_roles (role_code, label, description, eligible_principal_kind_code, is_human_review_role, is_publication_role) VALUES
  ('researcher_author', 'Researcher / author', 'Prepares curated unpublished drafts.', 'human', 1, 0),
  ('official_source_verifier', 'Official-source verifier', 'Independently verifies authoritative source support.', 'human', 1, 0),
  ('substantive_legal_reviewer', 'Substantive legal reviewer', 'Reviews legal meaning, scope, and atomicity.', 'human', 1, 0),
  ('local_jurisdiction_reviewer', 'Local-jurisdiction reviewer', 'Reviews national or subnational material within qualification scope.', 'human', 1, 0),
  ('translation_reviewer', 'Translation reviewer', 'Reviews non-authoritative translations.', 'human', 1, 0),
  ('editorial_quality_reviewer', 'Editorial/data-quality/accessibility reviewer', 'Reviews editorial quality, data quality, and accessibility.', 'human', 1, 0),
  ('publisher', 'Publisher', 'Makes independent publication decisions.', 'human', 1, 1),
  ('automated_monitor', 'Automated monitor', 'Runs auditable extraction or freshness checks without review authority.', 'service', 0, 0);

INSERT INTO atlas_qualification_types (qualification_type_code, label, description) VALUES
  ('official_source_verification', 'Official-source verification', 'Qualification to verify authoritative source identity and representation.'),
  ('substantive_legal_review', 'Substantive legal review', 'Qualification to review substantive legal content.'),
  ('local_jurisdiction_review', 'Local-jurisdiction review', 'Qualification scoped to a territorial jurisdiction.'),
  ('translation_review', 'Translation review', 'Qualification scoped to one or more languages.'),
  ('editorial_quality_review', 'Editorial/data-quality/accessibility review', 'Qualification to review editorial, data-quality, and accessibility requirements.'),
  ('publication_approval', 'Publication approval', 'Qualification to make an independent publication decision.');

INSERT INTO atlas_taxonomy_types (taxonomy_type_code, label, description) VALUES
  ('hiring_stage', 'Hiring stage', 'Stage in the hiring lifecycle.'),
  ('legal_lens', 'Legal lens', 'Cross-cutting legal or operational lens.'),
  ('actor_type', 'Actor type', 'Kind of responsible or affected actor.'),
  ('normative_role', 'Normative role', 'Semantic role an actor has in a proposition.'),
  ('protected_ground', 'Protected ground', 'Legal protected-ground vocabulary; distinct from data categories.'),
  ('data_category', 'Data category', 'Category of processed information; distinct from protected grounds.'),
  ('language', 'Language', 'BCP 47 language vocabulary.'),
  ('lifecycle_state', 'Lifecycle state', 'Legal-content workflow state.'),
  ('subject_area', 'Subject area', 'Qualification and review subject scope.');

INSERT INTO atlas_terms (taxonomy_type_id, term_code, created_at)
SELECT t.id, v.code, '2026-09-02T00:00:00.000Z' FROM atlas_taxonomy_types t JOIN (
  SELECT 'hiring_stage' type, 'job_design' code UNION ALL SELECT 'hiring_stage','advertising' UNION ALL SELECT 'hiring_stage','sourcing' UNION ALL SELECT 'hiring_stage','application' UNION ALL SELECT 'hiring_stage','screening' UNION ALL SELECT 'hiring_stage','assessment' UNION ALL SELECT 'hiring_stage','interview' UNION ALL SELECT 'hiring_stage','decision' UNION ALL SELECT 'hiring_stage','offer_pay' UNION ALL SELECT 'hiring_stage','onboarding' UNION ALL SELECT 'hiring_stage','retention' UNION ALL SELECT 'hiring_stage','audit' UNION ALL SELECT 'hiring_stage','redress' UNION ALL
  SELECT 'legal_lens','equality' UNION ALL SELECT 'legal_lens','accessibility_accommodation' UNION ALL SELECT 'legal_lens','data_protection' UNION ALL SELECT 'legal_lens','ai_automation' UNION ALL SELECT 'legal_lens','pay_transparency' UNION ALL SELECT 'legal_lens','employment_law' UNION ALL SELECT 'legal_lens','worker_participation' UNION ALL SELECT 'legal_lens','vendor_procurement' UNION ALL SELECT 'legal_lens','immigration_mobility' UNION ALL SELECT 'legal_lens','remedies' UNION ALL
  SELECT 'actor_type','employer' UNION ALL SELECT 'actor_type','recruiter' UNION ALL SELECT 'actor_type','hiring_manager' UNION ALL SELECT 'actor_type','ai_provider' UNION ALL SELECT 'actor_type','ai_deployer' UNION ALL SELECT 'actor_type','platform' UNION ALL SELECT 'actor_type','processor' UNION ALL SELECT 'actor_type','public_authority' UNION ALL SELECT 'actor_type','worker_representative' UNION ALL
  SELECT 'normative_role','duty_bearer' UNION ALL SELECT 'normative_role','rights_holder' UNION ALL SELECT 'normative_role','beneficiary' UNION ALL SELECT 'normative_role','decision_maker' UNION ALL SELECT 'normative_role','provider' UNION ALL SELECT 'normative_role','deployer' UNION ALL SELECT 'normative_role','processor' UNION ALL SELECT 'normative_role','enforcer' UNION ALL SELECT 'normative_role','representative' UNION ALL
  SELECT 'protected_ground','race_ethnicity' UNION ALL SELECT 'protected_ground','sex_gender' UNION ALL SELECT 'protected_ground','pregnancy_maternity' UNION ALL SELECT 'protected_ground','disability' UNION ALL SELECT 'protected_ground','age' UNION ALL SELECT 'protected_ground','religion_belief' UNION ALL SELECT 'protected_ground','sexual_orientation' UNION ALL SELECT 'protected_ground','nationality' UNION ALL SELECT 'protected_ground','union_membership' UNION ALL SELECT 'protected_ground','other' UNION ALL
  SELECT 'data_category','identity' UNION ALL SELECT 'data_category','contact' UNION ALL SELECT 'data_category','cv' UNION ALL SELECT 'data_category','assessment' UNION ALL SELECT 'data_category','health_disability' UNION ALL SELECT 'data_category','equality_monitoring' UNION ALL SELECT 'data_category','biometric' UNION ALL SELECT 'data_category','criminal' UNION ALL SELECT 'data_category','pay' UNION ALL SELECT 'data_category','inferred_profile' UNION ALL SELECT 'data_category','worker_data' UNION ALL
  SELECT 'language','en' UNION ALL
  SELECT 'lifecycle_state','quarantined' UNION ALL SELECT 'lifecycle_state','draft' UNION ALL SELECT 'lifecycle_state','reviewed' UNION ALL SELECT 'lifecycle_state','published' UNION ALL SELECT 'lifecycle_state','stale' UNION ALL SELECT 'lifecycle_state','withdrawn' UNION ALL
  SELECT 'subject_area','general_legal' UNION ALL SELECT 'subject_area','equality' UNION ALL SELECT 'subject_area','accessibility' UNION ALL SELECT 'subject_area','data_protection' UNION ALL SELECT 'subject_area','ai_automation' UNION ALL SELECT 'subject_area','pay_transparency'
) v ON v.type = t.taxonomy_type_code;

INSERT INTO atlas_hiring_stages (term_id, display_order)
SELECT id, CASE term_code WHEN 'job_design' THEN 1 WHEN 'advertising' THEN 2 WHEN 'sourcing' THEN 3 WHEN 'application' THEN 4 WHEN 'screening' THEN 5 WHEN 'assessment' THEN 6 WHEN 'interview' THEN 7 WHEN 'decision' THEN 8 WHEN 'offer_pay' THEN 9 WHEN 'onboarding' THEN 10 WHEN 'retention' THEN 11 WHEN 'audit' THEN 12 ELSE 13 END FROM atlas_terms WHERE taxonomy_type_id = (SELECT id FROM atlas_taxonomy_types WHERE taxonomy_type_code='hiring_stage');
INSERT INTO atlas_legal_lenses (term_id, display_order) SELECT id, row_number() OVER (ORDER BY id) FROM atlas_terms WHERE taxonomy_type_id=(SELECT id FROM atlas_taxonomy_types WHERE taxonomy_type_code='legal_lens');
INSERT INTO atlas_actor_types SELECT id FROM atlas_terms WHERE taxonomy_type_id=(SELECT id FROM atlas_taxonomy_types WHERE taxonomy_type_code='actor_type');
INSERT INTO atlas_normative_roles SELECT id FROM atlas_terms WHERE taxonomy_type_id=(SELECT id FROM atlas_taxonomy_types WHERE taxonomy_type_code='normative_role');
INSERT INTO atlas_protected_grounds SELECT id FROM atlas_terms WHERE taxonomy_type_id=(SELECT id FROM atlas_taxonomy_types WHERE taxonomy_type_code='protected_ground');
INSERT INTO atlas_data_categories SELECT id FROM atlas_terms WHERE taxonomy_type_id=(SELECT id FROM atlas_taxonomy_types WHERE taxonomy_type_code='data_category');
INSERT INTO atlas_languages SELECT id, term_code FROM atlas_terms WHERE taxonomy_type_id=(SELECT id FROM atlas_taxonomy_types WHERE taxonomy_type_code='language');
INSERT INTO atlas_lifecycle_states SELECT id FROM atlas_terms WHERE taxonomy_type_id=(SELECT id FROM atlas_taxonomy_types WHERE taxonomy_type_code='lifecycle_state');
INSERT INTO atlas_subject_areas SELECT id FROM atlas_terms WHERE taxonomy_type_id=(SELECT id FROM atlas_taxonomy_types WHERE taxonomy_type_code='subject_area');

INSERT INTO atlas_review_gates (gate_code, label, description) VALUES
  ('official_source_verification', 'Official-source verification', 'Independent verification of authoritative immutable source support.'),
  ('substantive_legal_review', 'Substantive legal review', 'Independent legal review of exact immutable content.'),
  ('local_jurisdiction_review', 'Local-jurisdiction review', 'Conditional qualified review for national material.'),
  ('translation_review', 'Translation review', 'Conditional review of non-authoritative translations.'),
  ('editorial_quality_review', 'Editorial/data-quality/accessibility review', 'Independent editorial, data-quality, and accessibility review.'),
  ('publication_approval', 'Publication approval', 'Independent fail-closed publication decision.');

INSERT INTO atlas_review_policies (policy_code, transition_code, label, description, created_at) VALUES
  ('candidate_to_draft', 'candidate_to_draft', 'Candidate to curated draft', 'Requires independent official-source verification before researcher promotion.', '2026-09-02T00:00:00.000Z'),
  ('proposition_to_public', 'proposition_to_public', 'Proposition version to public eligibility', 'Requires non-waivable source, legal, editorial, conditional local/translation, and publication gates.', '2026-09-02T00:00:00.000Z');

INSERT INTO atlas_review_policy_versions (review_policy_id, version_number, valid_from, content_hash, created_at) VALUES
  ((SELECT id FROM atlas_review_policies WHERE policy_code='candidate_to_draft'), 1, '2026-09-02', 'bb820958040cf521e8f4050ae9333e36a1799f01a791a13c3bd973a0afa39cb3', '2026-09-02T00:00:00.000Z'),
  ((SELECT id FROM atlas_review_policies WHERE policy_code='proposition_to_public'), 1, '2026-09-02', '1a165c05e3841a3fd319aa51772a70d9f7945928e17f86987bcc1c46d0d589b0', '2026-09-02T00:00:00.000Z');

INSERT INTO atlas_review_policy_requirements (review_policy_version_id, review_gate_id, review_role_id, qualification_type_id, condition_code, minimum_approvals, is_human_only, is_qualification_required, is_jurisdiction_match_required, maximum_review_age_days, sequence_number, is_non_waivable)
VALUES ((SELECT v.id FROM atlas_review_policy_versions v JOIN atlas_review_policies p ON p.id=v.review_policy_id WHERE p.policy_code='candidate_to_draft'), (SELECT id FROM atlas_review_gates WHERE gate_code='official_source_verification'), (SELECT id FROM atlas_review_roles WHERE role_code='official_source_verifier'), (SELECT id FROM atlas_qualification_types WHERE qualification_type_code='official_source_verification'), 'always', 1, 1, 1, 0, 365, 1, 1);

INSERT INTO atlas_review_policy_requirements (review_policy_version_id, review_gate_id, review_role_id, qualification_type_id, condition_code, minimum_approvals, is_human_only, is_qualification_required, is_jurisdiction_match_required, maximum_review_age_days, sequence_number, is_non_waivable)
SELECT v.id, g.id, r.id, q.id, x.condition_code, 1, 1, 1, x.jurisdiction_match, x.max_age, x.sequence_number, 1
FROM atlas_review_policy_versions v JOIN atlas_review_policies p ON p.id=v.review_policy_id
JOIN (
  SELECT 'official_source_verification' gate_code, 'official_source_verifier' role_code, 'official_source_verification' qualification_code, 'always' condition_code, 0 jurisdiction_match, 365 max_age, 1 sequence_number UNION ALL
  SELECT 'substantive_legal_review','substantive_legal_reviewer','substantive_legal_review','always',0,365,2 UNION ALL
  SELECT 'local_jurisdiction_review','local_jurisdiction_reviewer','local_jurisdiction_review','national_material',1,365,3 UNION ALL
  SELECT 'translation_review','translation_reviewer','translation_review','non_authoritative_translation',0,365,4 UNION ALL
  SELECT 'editorial_quality_review','editorial_quality_reviewer','editorial_quality_review','always',0,365,5 UNION ALL
  SELECT 'publication_approval','publisher','publication_approval','always',0,365,6
) x
JOIN atlas_review_gates g ON g.gate_code=x.gate_code
JOIN atlas_review_roles r ON r.role_code=x.role_code
JOIN atlas_qualification_types q ON q.qualification_type_code=x.qualification_code
WHERE p.policy_code='proposition_to_public';

INSERT INTO atlas_review_policy_separation_rules (review_policy_version_id, left_review_role_id, right_review_role_id, rule_code)
SELECT v.id, l.id, r.id, 'different_principal' FROM atlas_review_policy_versions v
JOIN atlas_review_policies p ON p.id=v.review_policy_id
JOIN (
  SELECT 'researcher_author' left_code, 'substantive_legal_reviewer' right_code UNION ALL
  SELECT 'researcher_author','publisher' UNION ALL
  SELECT 'substantive_legal_reviewer','publisher'
) x
JOIN atlas_review_roles l ON l.role_code=x.left_code
JOIN atlas_review_roles r ON r.role_code=x.right_code
WHERE p.policy_code='proposition_to_public';

INSERT INTO atlas_review_policy_version_seals (review_policy_version_id, sealed_at, canonical_payload_hash)
SELECT id, '2026-09-02T00:00:00.000Z', content_hash FROM atlas_review_policy_versions;

COMMIT;
