PRAGMA foreign_keys = ON;
PRAGMA recursive_triggers = ON;

CREATE TABLE atlas_evidence_bundle_receipts (
  id INTEGER PRIMARY KEY CHECK (id > 0),
  bundle_sequence INTEGER NOT NULL CHECK (bundle_sequence > 0),
  bundle_code TEXT NOT NULL,
  format_version_code TEXT NOT NULL CHECK (format_version_code = '1.0.0'),
  bundle_digest_sha256 TEXT NOT NULL,
  manifest_path TEXT NOT NULL,
  bundle_created_at TEXT NOT NULL,
  submitted_by_principal_id INTEGER NOT NULL REFERENCES atlas_principals(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  imported_by_principal_id INTEGER NOT NULL REFERENCES atlas_principals(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  importer_software_code TEXT NOT NULL,
  importer_version TEXT NOT NULL,
  recorded_by_principal_id INTEGER NOT NULL REFERENCES atlas_principals(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  recorded_at TEXT NOT NULL,
  CHECK (length(CAST(bundle_code AS BLOB)) BETWEEN 3 AND 80 AND instr(bundle_code,char(0))=0 AND bundle_code=lower(bundle_code) AND bundle_code NOT GLOB '*[^a-z0-9._-]*' AND substr(bundle_code,1,1) GLOB '[a-z0-9]' AND substr(bundle_code,-1,1) GLOB '[a-z0-9]'),
  CHECK (length(CAST(bundle_digest_sha256 AS BLOB))=64 AND instr(bundle_digest_sha256,char(0))=0 AND bundle_digest_sha256=lower(bundle_digest_sha256) AND bundle_digest_sha256 NOT GLOB '*[^0-9a-f]*'),
  CHECK (length(CAST(manifest_path AS BLOB)) BETWEEN 1 AND 240 AND instr(manifest_path,char(0))=0 AND manifest_path=trim(manifest_path) AND substr(manifest_path,1,1)<>'/' AND instr(manifest_path,'\\')=0 AND manifest_path NOT GLOB '*[^A-Za-z0-9._/-]*' AND manifest_path NOT LIKE './%' AND manifest_path NOT LIKE '%/./%' AND manifest_path NOT LIKE '%/.' AND manifest_path NOT LIKE '%//%' AND manifest_path<>'..' AND manifest_path NOT LIKE '../%' AND manifest_path NOT LIKE '%/../%' AND manifest_path NOT LIKE '%/..'),
  CHECK (length(CAST(importer_software_code AS BLOB)) BETWEEN 1 AND 80 AND instr(importer_software_code,char(0))=0 AND importer_software_code=trim(importer_software_code)),
  CHECK (length(CAST(importer_version AS BLOB)) BETWEEN 1 AND 80 AND instr(importer_version,char(0))=0 AND importer_version=trim(importer_version)),
  CHECK (length(CAST(bundle_created_at AS BLOB))=24 AND instr(bundle_created_at,char(0))=0 AND bundle_created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' AND julianday(bundle_created_at) IS NOT NULL AND strftime('%Y-%m-%dT%H:%M:%fZ',julianday(bundle_created_at))=bundle_created_at),
  CHECK (length(CAST(recorded_at AS BLOB))=24 AND instr(recorded_at,char(0))=0 AND recorded_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' AND julianday(recorded_at) IS NOT NULL AND strftime('%Y-%m-%dT%H:%M:%fZ',julianday(recorded_at))=recorded_at),
  CHECK (recorded_by_principal_id = submitted_by_principal_id AND recorded_at = bundle_created_at)
) STRICT;

CREATE TABLE atlas_retrieval_locations (
  id INTEGER PRIMARY KEY CHECK (id > 0),
  location_code TEXT NOT NULL,
  location_url TEXT NOT NULL,
  evidence_bundle_receipt_id INTEGER NOT NULL REFERENCES atlas_evidence_bundle_receipts(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  recorded_by_principal_id INTEGER NOT NULL REFERENCES atlas_principals(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  recorded_at TEXT NOT NULL,
  CHECK (length(CAST(location_code AS BLOB)) BETWEEN 3 AND 120 AND instr(location_code,char(0))=0 AND location_code=lower(location_code) AND location_code NOT GLOB '*[^a-z0-9._-]*' AND substr(location_code,1,1) GLOB '[a-z0-9]' AND substr(location_code,-1,1) GLOB '[a-z0-9]'),
  CHECK (length(CAST(location_url AS BLOB)) BETWEEN 9 AND 2048 AND instr(location_url,char(0))=0 AND location_url=trim(location_url) AND substr(location_url,1,8)='https://' AND instr(location_url,'@')=0 AND instr(location_url,'\\')=0 AND location_url NOT GLOB '*'||char(9)||'*' AND location_url NOT GLOB '*'||char(10)||'*' AND location_url NOT GLOB '*'||char(13)||'*'),
  CHECK (length(CAST(recorded_at AS BLOB))=24 AND recorded_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' AND julianday(recorded_at) IS NOT NULL AND strftime('%Y-%m-%dT%H:%M:%fZ',julianday(recorded_at))=recorded_at)
) STRICT;

CREATE TABLE atlas_artifacts (
  id INTEGER PRIMARY KEY CHECK (id > 0),
  artifact_code TEXT NOT NULL,
  byte_layer_code TEXT NOT NULL CHECK (byte_layer_code IN ('retrieved_body','derived_output')),
  hash_algorithm_code TEXT NOT NULL CHECK (hash_algorithm_code = 'sha256'),
  sha256 TEXT NOT NULL,
  byte_length INTEGER NOT NULL CHECK (byte_length >= 0),
  evidence_bundle_receipt_id INTEGER NOT NULL REFERENCES atlas_evidence_bundle_receipts(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  recorded_by_principal_id INTEGER NOT NULL REFERENCES atlas_principals(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  recorded_at TEXT NOT NULL,
  CHECK (length(CAST(artifact_code AS BLOB)) BETWEEN 64 AND 180 AND instr(artifact_code,char(0))=0 AND artifact_code=lower(artifact_code) AND artifact_code NOT GLOB '*[^a-z0-9._-]*'),
  CHECK (length(CAST(sha256 AS BLOB))=64 AND instr(sha256,char(0))=0 AND sha256=lower(sha256) AND sha256 NOT GLOB '*[^0-9a-f]*'),
  CHECK (artifact_code = 'artifact.' || byte_layer_code || '.sha256.' || sha256 || '.' || CAST(byte_length AS TEXT)),
  CHECK (length(CAST(recorded_at AS BLOB))=24 AND recorded_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' AND julianday(recorded_at) IS NOT NULL AND strftime('%Y-%m-%dT%H:%M:%fZ',julianday(recorded_at))=recorded_at)
) STRICT;

CREATE TABLE atlas_retrieval_events (
  id INTEGER PRIMARY KEY CHECK (id > 0),
  retrieval_event_code TEXT NOT NULL,
  requested_location_id INTEGER NOT NULL REFERENCES atlas_retrieval_locations(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  last_attempted_location_id INTEGER NOT NULL REFERENCES atlas_retrieval_locations(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  resolved_location_id INTEGER REFERENCES atlas_retrieval_locations(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  conditional_basis_retrieval_event_id INTEGER REFERENCES atlas_retrieval_events(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  conditional_validator_kind_code TEXT CHECK (conditional_validator_kind_code IN ('etag','last_modified')),
  conditional_validator_value TEXT,
  artifact_id INTEGER REFERENCES atlas_artifacts(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  outcome_code TEXT NOT NULL CHECK (outcome_code IN ('retrieved_retained','observed_not_retained','not_modified','network_failed','http_failed')),
  request_method_code TEXT NOT NULL CHECK (request_method_code = 'GET'),
  request_profile_code TEXT NOT NULL CHECK (request_profile_code = 'http_get_representation_v1'),
  request_accept TEXT,
  request_accept_language TEXT,
  request_accept_encoding TEXT,
  started_at TEXT NOT NULL,
  completed_at TEXT NOT NULL,
  captured_at TEXT,
  http_status_code INTEGER CHECK (http_status_code BETWEEN 100 AND 599),
  response_etag TEXT,
  response_last_modified TEXT,
  response_content_type TEXT,
  response_content_length INTEGER CHECK (response_content_length >= 0),
  response_content_encoding TEXT,
  response_vary TEXT,
  detected_media_type TEXT,
  observed_sha256 TEXT,
  observed_byte_length INTEGER CHECK (observed_byte_length >= 0),
  collector_principal_id INTEGER NOT NULL REFERENCES atlas_principals(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  collector_software_code TEXT NOT NULL,
  collector_version TEXT NOT NULL,
  evidence_bundle_receipt_id INTEGER NOT NULL REFERENCES atlas_evidence_bundle_receipts(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  recorded_by_principal_id INTEGER NOT NULL REFERENCES atlas_principals(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  recorded_at TEXT NOT NULL,
  CHECK (length(CAST(retrieval_event_code AS BLOB)) BETWEEN 3 AND 160 AND instr(retrieval_event_code,char(0))=0 AND retrieval_event_code=lower(retrieval_event_code) AND retrieval_event_code NOT GLOB '*[^a-z0-9._-]*' AND substr(retrieval_event_code,1,1) GLOB '[a-z0-9]' AND substr(retrieval_event_code,-1,1) GLOB '[a-z0-9]'),
  CHECK (length(CAST(started_at AS BLOB))=24 AND started_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' AND julianday(started_at) IS NOT NULL AND strftime('%Y-%m-%dT%H:%M:%fZ',julianday(started_at))=started_at),
  CHECK (length(CAST(completed_at AS BLOB))=24 AND completed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' AND julianday(completed_at) IS NOT NULL AND strftime('%Y-%m-%dT%H:%M:%fZ',julianday(completed_at))=completed_at AND completed_at>=started_at),
  CHECK (captured_at IS NULL OR (length(CAST(captured_at AS BLOB))=24 AND captured_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' AND julianday(captured_at) IS NOT NULL AND strftime('%Y-%m-%dT%H:%M:%fZ',julianday(captured_at))=captured_at AND captured_at BETWEEN started_at AND completed_at)),
  CHECK (length(CAST(recorded_at AS BLOB))=24 AND recorded_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' AND julianday(recorded_at) IS NOT NULL AND strftime('%Y-%m-%dT%H:%M:%fZ',julianday(recorded_at))=recorded_at AND recorded_at>=completed_at),
  CHECK (length(CAST(collector_software_code AS BLOB)) BETWEEN 1 AND 80 AND instr(collector_software_code,char(0))=0 AND collector_software_code=trim(collector_software_code)),
  CHECK (length(CAST(collector_version AS BLOB)) BETWEEN 1 AND 80 AND instr(collector_version,char(0))=0 AND collector_version=trim(collector_version)),
  CHECK (request_accept IS NULL OR (length(CAST(request_accept AS BLOB)) BETWEEN 1 AND 512 AND instr(request_accept,char(0))=0 AND request_accept NOT GLOB ('*['||char(1)||'-'||char(31)||char(127)||']*') AND request_accept=trim(request_accept))),
  CHECK (request_accept_language IS NULL OR (length(CAST(request_accept_language AS BLOB)) BETWEEN 1 AND 512 AND instr(request_accept_language,char(0))=0 AND request_accept_language NOT GLOB ('*['||char(1)||'-'||char(31)||char(127)||']*') AND request_accept_language=trim(request_accept_language))),
  CHECK (request_accept_encoding IS NULL OR (length(CAST(request_accept_encoding AS BLOB)) BETWEEN 1 AND 512 AND instr(request_accept_encoding,char(0))=0 AND request_accept_encoding NOT GLOB ('*['||char(1)||'-'||char(31)||char(127)||']*') AND request_accept_encoding=trim(request_accept_encoding))),
  CHECK (
    (conditional_basis_retrieval_event_id IS NULL AND conditional_validator_kind_code IS NULL AND conditional_validator_value IS NULL)
    OR
    (conditional_basis_retrieval_event_id IS NOT NULL AND conditional_validator_kind_code IS NOT NULL AND conditional_validator_value IS NOT NULL
      AND length(CAST(conditional_validator_value AS BLOB)) BETWEEN 1 AND 512
      AND instr(conditional_validator_value,char(0))=0
      AND conditional_validator_value NOT GLOB ('*['||char(1)||'-'||char(31)||char(127)||']*')
      AND (
        (conditional_validator_kind_code='etag' AND (
          (length(CAST(conditional_validator_value AS BLOB))>=2 AND substr(conditional_validator_value,1,1)='"' AND substr(conditional_validator_value,-1,1)='"' AND instr(substr(conditional_validator_value,2,length(conditional_validator_value)-2),'"')=0 AND substr(conditional_validator_value,2,length(conditional_validator_value)-2) NOT GLOB '*[^!#-~]*')
          OR
          (length(CAST(conditional_validator_value AS BLOB))>=4 AND substr(conditional_validator_value,1,3)='W/"' AND substr(conditional_validator_value,-1,1)='"' AND instr(substr(conditional_validator_value,4,length(conditional_validator_value)-4),'"')=0 AND substr(conditional_validator_value,4,length(conditional_validator_value)-4) NOT GLOB '*[^!#-~]*')
        ))
        OR
        (conditional_validator_kind_code='last_modified' AND length(CAST(conditional_validator_value AS BLOB))=29 AND conditional_validator_value GLOB '[A-Z][a-z][a-z], [0-9][0-9] [A-Z][a-z][a-z] [0-9][0-9][0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9] GMT' AND substr(conditional_validator_value,1,3) IN ('Mon','Tue','Wed','Thu','Fri','Sat','Sun') AND CAST(substr(conditional_validator_value,6,2) AS INTEGER) BETWEEN 1 AND 31 AND substr(conditional_validator_value,9,3) IN ('Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec') AND CAST(substr(conditional_validator_value,18,2) AS INTEGER) BETWEEN 0 AND 23 AND CAST(substr(conditional_validator_value,21,2) AS INTEGER) BETWEEN 0 AND 59 AND CAST(substr(conditional_validator_value,24,2) AS INTEGER) BETWEEN 0 AND 59)
      )
    )
  ),
  CHECK (response_etag IS NULL OR (length(CAST(response_etag AS BLOB)) BETWEEN 2 AND 512 AND instr(response_etag,char(0))=0 AND response_etag NOT GLOB ('*['||char(1)||'-'||char(31)||char(127)||']*') AND ((substr(response_etag,1,1)='"' AND substr(response_etag,-1,1)='"' AND instr(substr(response_etag,2,length(response_etag)-2),'"')=0 AND substr(response_etag,2,length(response_etag)-2) NOT GLOB '*[^!#-~]*') OR (length(CAST(response_etag AS BLOB))>=4 AND substr(response_etag,1,3)='W/"' AND substr(response_etag,-1,1)='"' AND instr(substr(response_etag,4,length(response_etag)-4),'"')=0 AND substr(response_etag,4,length(response_etag)-4) NOT GLOB '*[^!#-~]*')))),
  CHECK (response_last_modified IS NULL OR (length(CAST(response_last_modified AS BLOB))=29 AND instr(response_last_modified,char(0))=0 AND response_last_modified NOT GLOB ('*['||char(1)||'-'||char(31)||char(127)||']*') AND response_last_modified GLOB '[A-Z][a-z][a-z], [0-9][0-9] [A-Z][a-z][a-z] [0-9][0-9][0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9] GMT' AND substr(response_last_modified,1,3) IN ('Mon','Tue','Wed','Thu','Fri','Sat','Sun') AND CAST(substr(response_last_modified,6,2) AS INTEGER) BETWEEN 1 AND 31 AND substr(response_last_modified,9,3) IN ('Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec') AND CAST(substr(response_last_modified,18,2) AS INTEGER) BETWEEN 0 AND 23 AND CAST(substr(response_last_modified,21,2) AS INTEGER) BETWEEN 0 AND 59 AND CAST(substr(response_last_modified,24,2) AS INTEGER) BETWEEN 0 AND 59)),
  CHECK (response_content_type IS NULL OR (length(CAST(response_content_type AS BLOB)) BETWEEN 1 AND 255 AND instr(response_content_type,char(0))=0 AND response_content_type NOT GLOB ('*['||char(1)||'-'||char(31)||char(127)||']*') AND response_content_type=trim(response_content_type))),
  CHECK (response_content_encoding IS NULL OR (length(CAST(response_content_encoding AS BLOB)) BETWEEN 1 AND 255 AND instr(response_content_encoding,char(0))=0 AND response_content_encoding NOT GLOB ('*['||char(1)||'-'||char(31)||char(127)||']*') AND response_content_encoding=trim(response_content_encoding) AND response_content_encoding=lower(response_content_encoding) AND response_content_encoding NOT GLOB '*[^a-z0-9!#$%&''*+.^_`|~, -]*' AND response_content_encoding NOT LIKE '%,,%' AND response_content_encoding NOT LIKE '%,  %')),
  CHECK (response_vary IS NULL OR (length(CAST(response_vary AS BLOB)) BETWEEN 1 AND 512 AND instr(response_vary,char(0))=0 AND response_vary NOT GLOB ('*['||char(1)||'-'||char(31)||char(127)||']*') AND response_vary=trim(response_vary) AND response_vary=lower(response_vary) AND (response_vary='*' OR instr(response_vary,'*')=0))),
  CHECK (detected_media_type IS NULL OR (length(CAST(detected_media_type AS BLOB)) BETWEEN 1 AND 255 AND instr(detected_media_type,char(0))=0 AND detected_media_type NOT GLOB ('*['||char(1)||'-'||char(31)||char(127)||']*') AND detected_media_type=trim(detected_media_type))),
  CHECK (CASE
    WHEN observed_sha256 IS NULL AND observed_byte_length IS NULL THEN 1
    WHEN outcome_code='observed_not_retained' AND observed_sha256 IS NOT NULL AND observed_byte_length IS NOT NULL
      AND length(CAST(observed_sha256 AS BLOB))=64 AND instr(observed_sha256,char(0))=0
      AND observed_sha256=lower(observed_sha256) AND observed_sha256 NOT GLOB '*[^0-9a-f]*' THEN 1
    ELSE 0
  END = 1),
  CHECK (CASE outcome_code
    WHEN 'retrieved_retained' THEN CASE WHEN
      resolved_location_id IS NOT NULL AND resolved_location_id=last_attempted_location_id
      AND artifact_id IS NOT NULL AND captured_at IS NOT NULL AND http_status_code IS 200
      AND observed_sha256 IS NULL AND observed_byte_length IS NULL AND detected_media_type IS NOT NULL
      THEN 1 ELSE 0 END
    WHEN 'observed_not_retained' THEN CASE WHEN
      resolved_location_id IS NOT NULL AND resolved_location_id=last_attempted_location_id
      AND artifact_id IS NULL AND captured_at IS NOT NULL AND http_status_code IS 200
      AND detected_media_type IS NOT NULL
      THEN 1 ELSE 0 END
    WHEN 'not_modified' THEN CASE WHEN
      resolved_location_id IS NOT NULL AND resolved_location_id=last_attempted_location_id
      AND artifact_id IS NULL AND captured_at IS NULL AND http_status_code IS 304
      AND conditional_basis_retrieval_event_id IS NOT NULL
      AND observed_sha256 IS NULL AND observed_byte_length IS NULL AND detected_media_type IS NULL
      THEN 1 ELSE 0 END
    WHEN 'network_failed' THEN CASE WHEN
      resolved_location_id IS NULL AND artifact_id IS NULL AND captured_at IS NULL AND http_status_code IS NULL
      AND observed_sha256 IS NULL AND observed_byte_length IS NULL
      AND response_etag IS NULL AND response_last_modified IS NULL AND response_content_type IS NULL
      AND response_content_length IS NULL AND response_content_encoding IS NULL AND response_vary IS NULL
      AND detected_media_type IS NULL
      THEN 1 ELSE 0 END
    WHEN 'http_failed' THEN CASE WHEN
      resolved_location_id IS NOT NULL AND resolved_location_id=last_attempted_location_id
      AND artifact_id IS NULL AND captured_at IS NULL AND http_status_code IS NOT NULL
      AND http_status_code BETWEEN 300 AND 599 AND http_status_code<>304
      AND observed_sha256 IS NULL AND observed_byte_length IS NULL AND detected_media_type IS NULL
      THEN 1 ELSE 0 END
    ELSE 0
  END = 1)
) STRICT;

CREATE TABLE atlas_retrieval_redirects (
  id INTEGER PRIMARY KEY CHECK (id > 0),
  redirect_code TEXT NOT NULL,
  retrieval_event_id INTEGER NOT NULL REFERENCES atlas_retrieval_events(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  hop_ordinal INTEGER NOT NULL CHECK (hop_ordinal > 0),
  from_location_id INTEGER NOT NULL REFERENCES atlas_retrieval_locations(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  to_location_id INTEGER NOT NULL REFERENCES atlas_retrieval_locations(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  http_status_code INTEGER NOT NULL CHECK (http_status_code IN (301,302,303,307,308)),
  evidence_bundle_receipt_id INTEGER NOT NULL REFERENCES atlas_evidence_bundle_receipts(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  recorded_by_principal_id INTEGER NOT NULL REFERENCES atlas_principals(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  recorded_at TEXT NOT NULL,
  CHECK (length(CAST(redirect_code AS BLOB)) BETWEEN 3 AND 160 AND instr(redirect_code,char(0))=0 AND redirect_code=lower(redirect_code) AND redirect_code NOT GLOB '*[^a-z0-9._-]*' AND substr(redirect_code,1,1) GLOB '[a-z0-9]' AND substr(redirect_code,-1,1) GLOB '[a-z0-9]'),
  CHECK (from_location_id<>to_location_id),
  CHECK (length(CAST(recorded_at AS BLOB))=24 AND recorded_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' AND julianday(recorded_at) IS NOT NULL AND strftime('%Y-%m-%dT%H:%M:%fZ',julianday(recorded_at))=recorded_at)
) STRICT;

CREATE TABLE atlas_artifact_custody_events (
  id INTEGER PRIMARY KEY CHECK (id > 0),
  custody_event_code TEXT NOT NULL,
  artifact_id INTEGER NOT NULL REFERENCES atlas_artifacts(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  copy_code TEXT NOT NULL,
  event_kind_code TEXT NOT NULL CHECK (event_kind_code IN ('placed','relocated','restricted','quarantined','restored','tombstoned')),
  predecessor_custody_event_id INTEGER REFERENCES atlas_artifact_custody_events(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  custody_class_code TEXT NOT NULL CHECK (custody_class_code IN ('repository','restricted_store')),
  backend_code TEXT,
  backend_reference TEXT,
  eligibility_declared_by_principal_id INTEGER REFERENCES atlas_principals(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  eligibility_declared_at TEXT,
  redistribution_eligible_declared INTEGER CHECK (redistribution_eligible_declared IN (0,1)),
  no_sensitive_data_declared INTEGER CHECK (no_sensitive_data_declared IN (0,1)),
  size_eligible_declared INTEGER CHECK (size_eligible_declared IN (0,1)),
  permanent_history_acknowledged INTEGER CHECK (permanent_history_acknowledged IN (0,1)),
  reason TEXT NOT NULL,
  occurred_at TEXT NOT NULL,
  evidence_bundle_receipt_id INTEGER NOT NULL REFERENCES atlas_evidence_bundle_receipts(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  recorded_by_principal_id INTEGER NOT NULL REFERENCES atlas_principals(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  recorded_at TEXT NOT NULL,
  CHECK (length(CAST(custody_event_code AS BLOB)) BETWEEN 3 AND 160 AND instr(custody_event_code,char(0))=0 AND custody_event_code=lower(custody_event_code) AND custody_event_code NOT GLOB '*[^a-z0-9._-]*' AND substr(custody_event_code,1,1) GLOB '[a-z0-9]' AND substr(custody_event_code,-1,1) GLOB '[a-z0-9]'),
  CHECK (length(CAST(copy_code AS BLOB)) BETWEEN 3 AND 120 AND instr(copy_code,char(0))=0 AND copy_code=lower(copy_code) AND copy_code NOT GLOB '*[^a-z0-9._-]*' AND substr(copy_code,1,1) GLOB '[a-z0-9]' AND substr(copy_code,-1,1) GLOB '[a-z0-9]'),
  CHECK (length(CAST(reason AS BLOB)) BETWEEN 1 AND 1000 AND instr(reason,char(0))=0 AND trim(reason,' '||char(9)||char(10)||char(11)||char(12)||char(13))<>''),
  CHECK ((event_kind_code='placed' AND predecessor_custody_event_id IS NULL) OR (event_kind_code<>'placed' AND predecessor_custody_event_id IS NOT NULL)),
  CHECK ((event_kind_code='tombstoned' AND backend_code IS NULL AND backend_reference IS NULL) OR (event_kind_code<>'tombstoned' AND backend_code IS NOT NULL AND backend_reference IS NOT NULL)),
  CHECK (event_kind_code NOT IN ('restricted','quarantined') OR custody_class_code='restricted_store'),
  CHECK (backend_code IS NULL OR (length(CAST(backend_code AS BLOB)) BETWEEN 1 AND 40 AND instr(backend_code,char(0))=0 AND backend_code=lower(backend_code) AND backend_code NOT GLOB '*[^a-z0-9._-]*' AND substr(backend_code,1,1) GLOB '[a-z0-9]' AND substr(backend_code,-1,1) GLOB '[a-z0-9]')),
  CHECK (backend_reference IS NULL OR (length(CAST(backend_reference AS BLOB)) BETWEEN 1 AND 512 AND instr(backend_reference,char(0))=0 AND backend_reference=trim(backend_reference) AND substr(backend_reference,1,1)<>'/' AND instr(backend_reference,'\\')=0 AND backend_reference NOT GLOB '*[^A-Za-z0-9._/-]*' AND backend_reference NOT LIKE './%' AND backend_reference NOT LIKE '%/./%' AND backend_reference NOT LIKE '%/.' AND backend_reference NOT LIKE '%//%' AND backend_reference<>'..' AND backend_reference NOT LIKE '../%' AND backend_reference NOT LIKE '%/../%' AND backend_reference NOT LIKE '%/..' AND instr(backend_reference,'?')=0)),
  CHECK (eligibility_declared_at IS NULL OR (length(CAST(eligibility_declared_at AS BLOB))=24 AND eligibility_declared_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' AND julianday(eligibility_declared_at) IS NOT NULL AND strftime('%Y-%m-%dT%H:%M:%fZ',julianday(eligibility_declared_at))=eligibility_declared_at)),
  CHECK (CASE
    WHEN event_kind_code<>'tombstoned' AND custody_class_code='repository' THEN CASE WHEN
      eligibility_declared_by_principal_id IS NOT NULL AND eligibility_declared_at IS NOT NULL
      AND redistribution_eligible_declared IS 1 AND no_sensitive_data_declared IS 1
      AND size_eligible_declared IS 1 AND permanent_history_acknowledged IS 1
      THEN 1 ELSE 0 END
    WHEN event_kind_code='tombstoned' OR custody_class_code='restricted_store' THEN CASE WHEN
      eligibility_declared_by_principal_id IS NULL AND eligibility_declared_at IS NULL
      AND redistribution_eligible_declared IS NULL AND no_sensitive_data_declared IS NULL
      AND size_eligible_declared IS NULL AND permanent_history_acknowledged IS NULL
      THEN 1 ELSE 0 END
    ELSE 0
  END = 1),
  CHECK (length(CAST(occurred_at AS BLOB))=24 AND occurred_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' AND julianday(occurred_at) IS NOT NULL AND strftime('%Y-%m-%dT%H:%M:%fZ',julianday(occurred_at))=occurred_at),
  CHECK (length(CAST(recorded_at AS BLOB))=24 AND recorded_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' AND julianday(recorded_at) IS NOT NULL AND strftime('%Y-%m-%dT%H:%M:%fZ',julianday(recorded_at))=recorded_at AND recorded_at>=occurred_at)
) STRICT;

CREATE TABLE atlas_processing_runs (
  id INTEGER PRIMARY KEY CHECK (id > 0),
  processing_run_code TEXT NOT NULL,
  run_ordinal INTEGER NOT NULL CHECK (run_ordinal >= 0),
  input_artifact_id INTEGER NOT NULL REFERENCES atlas_artifacts(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  method_code TEXT NOT NULL CHECK (method_code IN ('content_decoding','parser','ocr','normalization','manual_transcription')),
  processor_principal_id INTEGER NOT NULL REFERENCES atlas_principals(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  processor_software_code TEXT NOT NULL,
  processor_version TEXT NOT NULL,
  configuration_sha256 TEXT NOT NULL,
  started_at TEXT NOT NULL,
  completed_at TEXT NOT NULL,
  outcome_code TEXT NOT NULL CHECK (outcome_code IN ('succeeded','failed')),
  failure_code TEXT,
  evidence_bundle_receipt_id INTEGER NOT NULL REFERENCES atlas_evidence_bundle_receipts(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  recorded_by_principal_id INTEGER NOT NULL REFERENCES atlas_principals(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  recorded_at TEXT NOT NULL,
  CHECK (length(CAST(processing_run_code AS BLOB)) BETWEEN 3 AND 160 AND instr(processing_run_code,char(0))=0 AND processing_run_code=lower(processing_run_code) AND processing_run_code NOT GLOB '*[^a-z0-9._-]*' AND substr(processing_run_code,1,1) GLOB '[a-z0-9]' AND substr(processing_run_code,-1,1) GLOB '[a-z0-9]'),
  CHECK (length(CAST(processor_software_code AS BLOB)) BETWEEN 1 AND 80 AND instr(processor_software_code,char(0))=0 AND processor_software_code=trim(processor_software_code)),
  CHECK (length(CAST(processor_version AS BLOB)) BETWEEN 1 AND 80 AND instr(processor_version,char(0))=0 AND processor_version=trim(processor_version)),
  CHECK (length(CAST(configuration_sha256 AS BLOB))=64 AND instr(configuration_sha256,char(0))=0 AND configuration_sha256=lower(configuration_sha256) AND configuration_sha256 NOT GLOB '*[^0-9a-f]*'),
  CHECK (length(CAST(started_at AS BLOB))=24 AND started_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' AND julianday(started_at) IS NOT NULL AND strftime('%Y-%m-%dT%H:%M:%fZ',julianday(started_at))=started_at),
  CHECK (length(CAST(completed_at AS BLOB))=24 AND completed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' AND julianday(completed_at) IS NOT NULL AND strftime('%Y-%m-%dT%H:%M:%fZ',julianday(completed_at))=completed_at AND completed_at>=started_at),
  CHECK (length(CAST(recorded_at AS BLOB))=24 AND recorded_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' AND julianday(recorded_at) IS NOT NULL AND strftime('%Y-%m-%dT%H:%M:%fZ',julianday(recorded_at))=recorded_at AND recorded_at>=completed_at),
  CHECK ((outcome_code='succeeded' AND failure_code IS NULL) OR (outcome_code='failed' AND failure_code IS NOT NULL AND length(CAST(failure_code AS BLOB)) BETWEEN 1 AND 80 AND instr(failure_code,char(0))=0))
) STRICT;

CREATE TABLE atlas_processing_outputs (
  id INTEGER PRIMARY KEY CHECK (id > 0),
  processing_output_code TEXT NOT NULL,
  processing_run_id INTEGER NOT NULL REFERENCES atlas_processing_runs(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  artifact_id INTEGER NOT NULL REFERENCES atlas_artifacts(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  output_ordinal INTEGER NOT NULL CHECK (output_ordinal >= 0),
  output_kind_code TEXT NOT NULL CHECK (output_kind_code IN ('decoded_body','normalized_text','extracted_text','ocr_text','structured_data','manual_transcript','diagnostic')),
  detected_media_type TEXT NOT NULL,
  produced_at TEXT NOT NULL,
  evidence_bundle_receipt_id INTEGER NOT NULL REFERENCES atlas_evidence_bundle_receipts(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  recorded_by_principal_id INTEGER NOT NULL REFERENCES atlas_principals(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  recorded_at TEXT NOT NULL,
  CHECK (length(CAST(processing_output_code AS BLOB)) BETWEEN 3 AND 160 AND instr(processing_output_code,char(0))=0 AND processing_output_code=lower(processing_output_code) AND processing_output_code NOT GLOB '*[^a-z0-9._-]*' AND substr(processing_output_code,1,1) GLOB '[a-z0-9]' AND substr(processing_output_code,-1,1) GLOB '[a-z0-9]'),
  CHECK (length(CAST(detected_media_type AS BLOB)) BETWEEN 1 AND 255 AND instr(detected_media_type,char(0))=0 AND detected_media_type=trim(detected_media_type)),
  CHECK (length(CAST(produced_at AS BLOB))=24 AND produced_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' AND julianday(produced_at) IS NOT NULL AND strftime('%Y-%m-%dT%H:%M:%fZ',julianday(produced_at))=produced_at),
  CHECK (length(CAST(recorded_at AS BLOB))=24 AND recorded_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' AND julianday(recorded_at) IS NOT NULL AND strftime('%Y-%m-%dT%H:%M:%fZ',julianday(recorded_at))=recorded_at)
) STRICT;

CREATE TABLE atlas_unverified_candidate_occurrences (
  id INTEGER PRIMARY KEY CHECK (id > 0),
  candidate_record_code TEXT NOT NULL,
  candidate_chain_code TEXT NOT NULL,
  record_kind_code TEXT NOT NULL CHECK (record_kind_code IN ('assertion','correction','withdrawal')),
  corrects_candidate_occurrence_id INTEGER REFERENCES atlas_unverified_candidate_occurrences(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  processing_run_id INTEGER NOT NULL REFERENCES atlas_processing_runs(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  processing_output_id INTEGER NOT NULL,
  claim_type_code TEXT NOT NULL,
  observed_value TEXT,
  normalized_value TEXT,
  confidence_basis_points INTEGER CHECK (confidence_basis_points BETWEEN 0 AND 10000),
  locator_kind_code TEXT NOT NULL CHECK (locator_kind_code IN ('byte_span','text_span')),
  locator_value TEXT NOT NULL,
  span_start INTEGER CHECK (span_start >= 0),
  span_end INTEGER CHECK (span_end > span_start),
  reason TEXT NOT NULL,
  evidence_bundle_receipt_id INTEGER NOT NULL REFERENCES atlas_evidence_bundle_receipts(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  recorded_by_principal_id INTEGER NOT NULL REFERENCES atlas_principals(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  recorded_at TEXT NOT NULL,
  FOREIGN KEY (processing_output_id,processing_run_id) REFERENCES atlas_processing_outputs(id,processing_run_id) ON UPDATE RESTRICT ON DELETE RESTRICT,
  CHECK (length(CAST(candidate_record_code AS BLOB)) BETWEEN 3 AND 160 AND instr(candidate_record_code,char(0))=0 AND candidate_record_code=lower(candidate_record_code) AND candidate_record_code NOT GLOB '*[^a-z0-9._-]*' AND substr(candidate_record_code,1,1) GLOB '[a-z0-9]' AND substr(candidate_record_code,-1,1) GLOB '[a-z0-9]'),
  CHECK (length(CAST(candidate_chain_code AS BLOB)) BETWEEN 3 AND 160 AND instr(candidate_chain_code,char(0))=0 AND candidate_chain_code=lower(candidate_chain_code) AND candidate_chain_code NOT GLOB '*[^a-z0-9._-]*' AND substr(candidate_chain_code,1,1) GLOB '[a-z0-9]' AND substr(candidate_chain_code,-1,1) GLOB '[a-z0-9]'),
  CHECK (length(CAST(claim_type_code AS BLOB)) BETWEEN 3 AND 80 AND instr(claim_type_code,char(0))=0 AND claim_type_code=lower(claim_type_code) AND claim_type_code NOT GLOB '*[^a-z0-9._-]*' AND substr(claim_type_code,1,1) GLOB '[a-z0-9]' AND substr(claim_type_code,-1,1) GLOB '[a-z0-9]'),
  CHECK (length(CAST(locator_value AS BLOB)) BETWEEN 1 AND 1000 AND instr(locator_value,char(0))=0 AND trim(locator_value,' '||char(9)||char(10)||char(11)||char(12)||char(13))<>''),
  CHECK (length(CAST(reason AS BLOB)) BETWEEN 1 AND 1000 AND instr(reason,char(0))=0 AND trim(reason,' '||char(9)||char(10)||char(11)||char(12)||char(13))<>''),
  CHECK (span_start IS NOT NULL AND span_end IS NOT NULL),
  CHECK ((record_kind_code='assertion' AND corrects_candidate_occurrence_id IS NULL AND observed_value IS NOT NULL) OR (record_kind_code='correction' AND corrects_candidate_occurrence_id IS NOT NULL AND observed_value IS NOT NULL) OR (record_kind_code='withdrawal' AND corrects_candidate_occurrence_id IS NOT NULL AND observed_value IS NULL AND normalized_value IS NULL AND confidence_basis_points IS NULL)),
  CHECK (observed_value IS NULL OR (length(CAST(observed_value AS BLOB)) BETWEEN 1 AND 8000 AND instr(observed_value,char(0))=0)),
  CHECK (normalized_value IS NULL OR (length(CAST(normalized_value AS BLOB)) BETWEEN 1 AND 8000 AND instr(normalized_value,char(0))=0)),
  CHECK (length(CAST(recorded_at AS BLOB))=24 AND recorded_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z' AND julianday(recorded_at) IS NOT NULL AND strftime('%Y-%m-%dT%H:%M:%fZ',julianday(recorded_at))=recorded_at)
) STRICT;

CREATE UNIQUE INDEX atlas_evidence_bundle_receipts_code_uidx ON atlas_evidence_bundle_receipts(bundle_code);
CREATE UNIQUE INDEX atlas_evidence_bundle_receipts_sequence_uidx ON atlas_evidence_bundle_receipts(bundle_sequence);
CREATE UNIQUE INDEX atlas_evidence_bundle_receipts_digest_uidx ON atlas_evidence_bundle_receipts(bundle_digest_sha256);
CREATE UNIQUE INDEX atlas_evidence_bundle_receipts_path_uidx ON atlas_evidence_bundle_receipts(manifest_path);
CREATE UNIQUE INDEX atlas_retrieval_locations_code_uidx ON atlas_retrieval_locations(location_code);
CREATE UNIQUE INDEX atlas_retrieval_locations_url_uidx ON atlas_retrieval_locations(location_url);
CREATE UNIQUE INDEX atlas_artifacts_code_uidx ON atlas_artifacts(artifact_code);
CREATE UNIQUE INDEX atlas_artifacts_identity_uidx ON atlas_artifacts(byte_layer_code,hash_algorithm_code,sha256,byte_length);
CREATE UNIQUE INDEX atlas_retrieval_events_code_uidx ON atlas_retrieval_events(retrieval_event_code);
CREATE INDEX atlas_retrieval_events_location_time_idx ON atlas_retrieval_events(requested_location_id,last_attempted_location_id,resolved_location_id,completed_at,id);
CREATE UNIQUE INDEX atlas_retrieval_redirects_code_uidx ON atlas_retrieval_redirects(redirect_code);
CREATE UNIQUE INDEX atlas_retrieval_redirects_event_ordinal_uidx ON atlas_retrieval_redirects(retrieval_event_id,hop_ordinal);
CREATE UNIQUE INDEX atlas_artifact_custody_events_code_uidx ON atlas_artifact_custody_events(custody_event_code);
CREATE UNIQUE INDEX atlas_artifact_custody_events_one_root_uidx ON atlas_artifact_custody_events(artifact_id,copy_code) WHERE predecessor_custody_event_id IS NULL;
CREATE UNIQUE INDEX atlas_artifact_custody_events_predecessor_uidx ON atlas_artifact_custody_events(predecessor_custody_event_id) WHERE predecessor_custody_event_id IS NOT NULL;
CREATE INDEX atlas_artifact_custody_events_leaf_idx ON atlas_artifact_custody_events(artifact_id,copy_code,occurred_at,evidence_bundle_receipt_id,id);
CREATE UNIQUE INDEX atlas_processing_runs_code_uidx ON atlas_processing_runs(processing_run_code);
CREATE UNIQUE INDEX atlas_processing_runs_receipt_ordinal_uidx ON atlas_processing_runs(evidence_bundle_receipt_id,run_ordinal);
CREATE INDEX atlas_processing_runs_input_time_idx ON atlas_processing_runs(input_artifact_id,evidence_bundle_receipt_id,run_ordinal,started_at,id);
CREATE UNIQUE INDEX atlas_processing_outputs_code_uidx ON atlas_processing_outputs(processing_output_code);
CREATE UNIQUE INDEX atlas_processing_outputs_run_ordinal_uidx ON atlas_processing_outputs(processing_run_id,output_ordinal);
CREATE UNIQUE INDEX atlas_processing_outputs_id_run_uidx ON atlas_processing_outputs(id,processing_run_id);
CREATE UNIQUE INDEX atlas_candidate_occurrences_record_code_uidx ON atlas_unverified_candidate_occurrences(candidate_record_code);
CREATE UNIQUE INDEX atlas_candidate_occurrences_one_root_uidx ON atlas_unverified_candidate_occurrences(candidate_chain_code) WHERE corrects_candidate_occurrence_id IS NULL;
CREATE UNIQUE INDEX atlas_candidate_occurrences_predecessor_uidx ON atlas_unverified_candidate_occurrences(corrects_candidate_occurrence_id) WHERE corrects_candidate_occurrence_id IS NOT NULL;
CREATE INDEX atlas_candidate_occurrences_leaf_idx ON atlas_unverified_candidate_occurrences(candidate_chain_code,recorded_at,id);
CREATE INDEX atlas_candidate_occurrences_run_output_idx ON atlas_unverified_candidate_occurrences(processing_run_id,processing_output_id,id);

CREATE TRIGGER atlas_evidence_bundle_receipts_validate_insert BEFORE INSERT ON atlas_evidence_bundle_receipts BEGIN
  SELECT CASE WHEN EXISTS(SELECT 1 FROM atlas_evidence_bundle_receipts WHERE id=NEW.id OR bundle_sequence=NEW.bundle_sequence OR bundle_code=NEW.bundle_code OR bundle_digest_sha256=NEW.bundle_digest_sha256 OR manifest_path=NEW.manifest_path) THEN RAISE(ABORT,'bundle receipt collision') END;
  SELECT CASE WHEN NEW.bundle_sequence<>(SELECT COALESCE(MAX(bundle_sequence),0)+1 FROM atlas_evidence_bundle_receipts) THEN RAISE(ABORT,'bundle sequence must be the next contiguous value') END;
  SELECT CASE WHEN EXISTS(SELECT 1 FROM atlas_evidence_bundle_receipts p WHERE p.bundle_sequence=NEW.bundle_sequence-1 AND p.bundle_created_at>NEW.bundle_created_at) THEN RAISE(ABORT,'bundle creation chronology must be monotonic') END;
  SELECT CASE WHEN NEW.submitted_by_principal_id=1 OR NEW.imported_by_principal_id=1 OR NOT EXISTS(SELECT 1 FROM atlas_principals p WHERE p.id=NEW.submitted_by_principal_id AND p.principal_kind_code='human' AND p.created_at<=NEW.bundle_created_at) OR NOT EXISTS(SELECT 1 FROM atlas_principals p WHERE p.id=NEW.imported_by_principal_id AND p.principal_kind_code='service' AND p.created_at<=NEW.bundle_created_at) THEN RAISE(ABORT,'bundle requires causal non-bootstrap human submitter and service importer') END;
END;

CREATE TRIGGER atlas_retrieval_locations_validate_insert BEFORE INSERT ON atlas_retrieval_locations BEGIN
  SELECT CASE WHEN EXISTS(SELECT 1 FROM atlas_retrieval_locations WHERE id=NEW.id OR location_code=NEW.location_code OR location_url=NEW.location_url) THEN RAISE(ABORT,'retrieval location collision') END;
  SELECT CASE WHEN NEW.recorded_by_principal_id=1 OR NOT EXISTS(SELECT 1 FROM atlas_evidence_bundle_receipts r JOIN atlas_principals p ON p.id=NEW.recorded_by_principal_id WHERE r.id=NEW.evidence_bundle_receipt_id AND r.submitted_by_principal_id=NEW.recorded_by_principal_id AND p.created_at<=NEW.recorded_at AND NEW.recorded_at<=r.bundle_created_at) THEN RAISE(ABORT,'invalid retrieval location attribution or chronology') END;
END;

CREATE TRIGGER atlas_artifacts_validate_insert BEFORE INSERT ON atlas_artifacts BEGIN
  SELECT CASE WHEN EXISTS(SELECT 1 FROM atlas_artifacts WHERE id=NEW.id OR artifact_code=NEW.artifact_code OR (byte_layer_code=NEW.byte_layer_code AND hash_algorithm_code=NEW.hash_algorithm_code AND sha256=NEW.sha256 AND byte_length=NEW.byte_length)) THEN RAISE(ABORT,'artifact identity collision') END;
  SELECT CASE WHEN NEW.recorded_by_principal_id=1 OR NOT EXISTS(SELECT 1 FROM atlas_evidence_bundle_receipts r JOIN atlas_principals p ON p.id=NEW.recorded_by_principal_id WHERE r.id=NEW.evidence_bundle_receipt_id AND r.submitted_by_principal_id=NEW.recorded_by_principal_id AND p.created_at<=NEW.recorded_at AND NEW.recorded_at<=r.bundle_created_at) THEN RAISE(ABORT,'invalid artifact attribution or chronology') END;
END;

CREATE TRIGGER atlas_retrieval_events_validate_insert BEFORE INSERT ON atlas_retrieval_events BEGIN
  SELECT CASE WHEN EXISTS(SELECT 1 FROM atlas_retrieval_events WHERE id=NEW.id OR retrieval_event_code=NEW.retrieval_event_code) THEN RAISE(ABORT,'retrieval event collision') END;
  SELECT CASE WHEN NEW.recorded_by_principal_id=1 OR NEW.collector_principal_id=1 OR NOT EXISTS(SELECT 1 FROM atlas_evidence_bundle_receipts r JOIN atlas_principals submitter ON submitter.id=NEW.recorded_by_principal_id JOIN atlas_principals collector ON collector.id=NEW.collector_principal_id WHERE r.id=NEW.evidence_bundle_receipt_id AND r.submitted_by_principal_id=NEW.recorded_by_principal_id AND r.imported_by_principal_id<>NEW.collector_principal_id AND submitter.created_at<=NEW.recorded_at AND collector.principal_kind_code='service' AND collector.created_at<=NEW.started_at AND NEW.recorded_at<=r.bundle_created_at) THEN RAISE(ABORT,'invalid retrieval event attribution or chronology') END;
  SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM atlas_retrieval_locations l WHERE l.id=NEW.requested_location_id AND l.recorded_at<=NEW.started_at) OR NOT EXISTS(SELECT 1 FROM atlas_retrieval_locations l WHERE l.id=NEW.last_attempted_location_id AND l.recorded_at<=NEW.completed_at) OR (NEW.resolved_location_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM atlas_retrieval_locations l WHERE l.id=NEW.resolved_location_id AND l.recorded_at<=NEW.completed_at)) THEN RAISE(ABORT,'retrieval event predates a location') END;
  SELECT CASE WHEN NEW.artifact_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM atlas_artifacts a WHERE a.id=NEW.artifact_id AND a.byte_layer_code='retrieved_body' AND a.recorded_at<=NEW.recorded_at) THEN RAISE(ABORT,'retrieval must reference a retrieved-body artifact') END;
  SELECT CASE WHEN NEW.conditional_basis_retrieval_event_id IS NOT NULL AND NOT EXISTS(
    SELECT 1 FROM atlas_retrieval_events b
    WHERE b.id=NEW.conditional_basis_retrieval_event_id
      AND b.requested_location_id=NEW.requested_location_id
      AND b.resolved_location_id=NEW.last_attempted_location_id
      AND b.outcome_code='retrieved_retained' AND b.http_status_code=200 AND b.artifact_id IS NOT NULL AND b.completed_at<NEW.started_at
      AND b.request_method_code=NEW.request_method_code AND b.request_profile_code=NEW.request_profile_code
      AND b.request_accept IS NEW.request_accept AND b.request_accept_language IS NEW.request_accept_language AND b.request_accept_encoding IS NEW.request_accept_encoding
      AND (b.response_vary IS NULL OR b.response_vary IN ('accept','accept-encoding','accept-language','accept, accept-encoding','accept, accept-language','accept-encoding, accept-language','accept, accept-encoding, accept-language'))
      AND (NEW.outcome_code<>'not_modified' OR (NEW.resolved_location_id=b.resolved_location_id AND (NEW.response_vary IS NULL OR NEW.response_vary IS b.response_vary)))
      AND ((NEW.conditional_validator_kind_code='etag' AND b.response_etag=NEW.conditional_validator_value) OR (NEW.conditional_validator_kind_code='last_modified' AND b.response_last_modified=NEW.conditional_validator_value))
  ) THEN RAISE(ABORT,'invalid conditional-request basis or representation profile') END;
END;

CREATE TRIGGER atlas_retrieval_redirects_validate_insert BEFORE INSERT ON atlas_retrieval_redirects BEGIN
  SELECT CASE WHEN EXISTS(SELECT 1 FROM atlas_retrieval_redirects WHERE id=NEW.id OR redirect_code=NEW.redirect_code OR (retrieval_event_id=NEW.retrieval_event_id AND hop_ordinal=NEW.hop_ordinal)) THEN RAISE(ABORT,'retrieval redirect collision') END;
  SELECT CASE WHEN NEW.recorded_by_principal_id=1 OR NOT EXISTS(SELECT 1 FROM atlas_retrieval_events e JOIN atlas_evidence_bundle_receipts r ON r.id=NEW.evidence_bundle_receipt_id WHERE e.id=NEW.retrieval_event_id AND e.evidence_bundle_receipt_id=NEW.evidence_bundle_receipt_id AND e.recorded_by_principal_id=NEW.recorded_by_principal_id AND e.recorded_at=NEW.recorded_at AND r.submitted_by_principal_id=NEW.recorded_by_principal_id) THEN RAISE(ABORT,'invalid redirect provenance') END;
  SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM atlas_retrieval_events e JOIN atlas_retrieval_locations f ON f.id=NEW.from_location_id JOIN atlas_retrieval_locations t ON t.id=NEW.to_location_id WHERE e.id=NEW.retrieval_event_id AND f.recorded_at<=e.completed_at AND t.recorded_at<=e.completed_at) THEN RAISE(ABORT,'redirect predates an endpoint location') END;
END;

CREATE TRIGGER atlas_artifact_custody_events_validate_insert BEFORE INSERT ON atlas_artifact_custody_events BEGIN
  SELECT CASE WHEN EXISTS(SELECT 1 FROM atlas_artifact_custody_events WHERE id=NEW.id OR custody_event_code=NEW.custody_event_code OR (NEW.predecessor_custody_event_id IS NULL AND predecessor_custody_event_id IS NULL AND artifact_id=NEW.artifact_id AND copy_code=NEW.copy_code) OR (NEW.predecessor_custody_event_id IS NOT NULL AND predecessor_custody_event_id=NEW.predecessor_custody_event_id)) THEN RAISE(ABORT,'custody event collision') END;
  SELECT CASE WHEN NEW.recorded_by_principal_id=1 OR NOT EXISTS(SELECT 1 FROM atlas_evidence_bundle_receipts r JOIN atlas_principals p ON p.id=NEW.recorded_by_principal_id JOIN atlas_artifacts a ON a.id=NEW.artifact_id WHERE r.id=NEW.evidence_bundle_receipt_id AND r.submitted_by_principal_id=NEW.recorded_by_principal_id AND p.created_at<=NEW.recorded_at AND a.recorded_at<=NEW.recorded_at AND NEW.recorded_at<=r.bundle_created_at) THEN RAISE(ABORT,'invalid custody attribution or chronology') END;
  SELECT CASE WHEN NEW.event_kind_code<>'tombstoned' AND NEW.backend_reference<>(SELECT 'objects/sha256/'||substr(a.sha256,1,2)||'/'||a.sha256 FROM atlas_artifacts a WHERE a.id=NEW.artifact_id) THEN RAISE(ABORT,'custody reference must be content addressed') END;
  SELECT CASE WHEN NEW.eligibility_declared_by_principal_id IS NOT NULL AND (NEW.eligibility_declared_by_principal_id<>NEW.recorded_by_principal_id OR NOT EXISTS(SELECT 1 FROM atlas_principals p WHERE p.id=NEW.eligibility_declared_by_principal_id AND p.principal_kind_code='human' AND p.id<>1 AND p.created_at<=NEW.eligibility_declared_at AND NEW.eligibility_declared_at<=NEW.recorded_at)) THEN RAISE(ABORT,'repository eligibility requires a causal submitter declaration') END;
  SELECT CASE WHEN NEW.predecessor_custody_event_id IS NULL AND EXISTS(SELECT 1 FROM atlas_artifact_custody_events WHERE artifact_id=NEW.artifact_id AND copy_code=NEW.copy_code AND predecessor_custody_event_id IS NULL) THEN RAISE(ABORT,'custody copy already has a root') END;
  SELECT CASE WHEN NEW.predecessor_custody_event_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM atlas_artifact_custody_events p WHERE p.id=NEW.predecessor_custody_event_id AND p.artifact_id=NEW.artifact_id AND p.copy_code=NEW.copy_code AND p.recorded_at<NEW.recorded_at AND p.occurred_at<=NEW.occurred_at AND NOT EXISTS(SELECT 1 FROM atlas_artifact_custody_events s WHERE s.predecessor_custody_event_id=p.id) AND ((NEW.event_kind_code='restored' AND p.event_kind_code IN ('restricted','quarantined','tombstoned')) OR (p.event_kind_code<>'tombstoned' AND ((NEW.event_kind_code='relocated' AND p.event_kind_code IN ('placed','relocated','restored') AND (NEW.backend_code<>p.backend_code OR NEW.custody_class_code<>p.custody_class_code)) OR NEW.event_kind_code IN ('restricted','quarantined','tombstoned'))))) THEN RAISE(ABORT,'invalid custody successor') END;
END;

CREATE TRIGGER atlas_processing_runs_validate_insert BEFORE INSERT ON atlas_processing_runs BEGIN
  SELECT CASE WHEN EXISTS(SELECT 1 FROM atlas_processing_runs WHERE id=NEW.id OR processing_run_code=NEW.processing_run_code OR (evidence_bundle_receipt_id=NEW.evidence_bundle_receipt_id AND run_ordinal=NEW.run_ordinal)) THEN RAISE(ABORT,'processing run collision') END;
  SELECT CASE WHEN NEW.run_ordinal<>(SELECT COALESCE(MAX(run_ordinal),-1)+1 FROM atlas_processing_runs WHERE evidence_bundle_receipt_id=NEW.evidence_bundle_receipt_id) THEN RAISE(ABORT,'processing run ordinal must be contiguous') END;
  SELECT CASE WHEN NEW.recorded_by_principal_id=1 OR NEW.processor_principal_id=1 OR NOT EXISTS(SELECT 1 FROM atlas_evidence_bundle_receipts r JOIN atlas_principals submitter ON submitter.id=NEW.recorded_by_principal_id JOIN atlas_principals processor ON processor.id=NEW.processor_principal_id JOIN atlas_artifacts a ON a.id=NEW.input_artifact_id WHERE r.id=NEW.evidence_bundle_receipt_id AND r.submitted_by_principal_id=NEW.recorded_by_principal_id AND r.imported_by_principal_id<>NEW.processor_principal_id AND submitter.created_at<=NEW.recorded_at AND processor.created_at<=NEW.started_at AND ((NEW.method_code='manual_transcription' AND processor.principal_kind_code='human') OR (NEW.method_code<>'manual_transcription' AND processor.principal_kind_code='service')) AND a.recorded_at<=NEW.started_at AND NEW.recorded_at<=r.bundle_created_at) THEN RAISE(ABORT,'invalid processing attribution or chronology') END;
  SELECT CASE WHEN NEW.method_code='content_decoding' AND NOT EXISTS(SELECT 1 FROM atlas_artifacts a WHERE a.id=NEW.input_artifact_id AND a.byte_layer_code='retrieved_body') THEN RAISE(ABORT,'content decoding requires a retrieved-body input') END;
  SELECT CASE WHEN NOT EXISTS(
    SELECT 1 FROM atlas_artifact_custody_events c
    JOIN atlas_evidence_bundle_receipts cr ON cr.id=c.evidence_bundle_receipt_id
    JOIN atlas_evidence_bundle_receipts rr ON rr.id=NEW.evidence_bundle_receipt_id
    WHERE c.artifact_id=NEW.input_artifact_id AND cr.bundle_sequence<=rr.bundle_sequence AND c.occurred_at<=NEW.started_at
      AND c.event_kind_code IN ('placed','relocated','restored')
      AND NOT EXISTS(SELECT 1 FROM atlas_artifact_custody_events s JOIN atlas_evidence_bundle_receipts sr ON sr.id=s.evidence_bundle_receipt_id WHERE s.predecessor_custody_event_id=c.id AND sr.bundle_sequence<=rr.bundle_sequence AND s.occurred_at<=NEW.started_at)
  ) THEN RAISE(ABORT,'processing input is not retained and available at its acceptance knowledge boundary') END;
  SELECT CASE WHEN NOT EXISTS(
    SELECT 1 FROM atlas_artifacts a
    JOIN atlas_evidence_bundle_receipts rr ON rr.id=NEW.evidence_bundle_receipt_id
    WHERE a.id=NEW.input_artifact_id AND (
      (a.byte_layer_code='retrieved_body' AND EXISTS(SELECT 1 FROM atlas_retrieval_events e JOIN atlas_evidence_bundle_receipts er ON er.id=e.evidence_bundle_receipt_id WHERE e.artifact_id=a.id AND e.outcome_code='retrieved_retained' AND e.captured_at<=NEW.started_at AND er.bundle_sequence<=rr.bundle_sequence))
      OR
      (a.byte_layer_code='derived_output' AND EXISTS(SELECT 1 FROM atlas_processing_outputs o JOIN atlas_processing_runs p ON p.id=o.processing_run_id JOIN atlas_evidence_bundle_receipts pr ON pr.id=p.evidence_bundle_receipt_id WHERE o.artifact_id=a.id AND (pr.bundle_sequence<rr.bundle_sequence OR (pr.bundle_sequence=rr.bundle_sequence AND p.run_ordinal<NEW.run_ordinal))))
    )
  ) THEN RAISE(ABORT,'processing input lacks an earlier grounded origin') END;
END;

CREATE TRIGGER atlas_processing_outputs_validate_insert BEFORE INSERT ON atlas_processing_outputs BEGIN
  SELECT CASE WHEN EXISTS(SELECT 1 FROM atlas_processing_outputs WHERE id=NEW.id OR processing_output_code=NEW.processing_output_code OR (processing_run_id=NEW.processing_run_id AND output_ordinal=NEW.output_ordinal)) THEN RAISE(ABORT,'processing output collision') END;
  SELECT CASE WHEN NOT EXISTS(
    SELECT 1 FROM atlas_processing_runs p WHERE p.id=NEW.processing_run_id AND (
      (p.method_code='content_decoding' AND NEW.output_kind_code='decoded_body')
      OR (p.method_code='parser' AND NEW.output_kind_code IN ('extracted_text','structured_data','diagnostic'))
      OR (p.method_code='ocr' AND NEW.output_kind_code IN ('ocr_text','diagnostic'))
      OR (p.method_code='normalization' AND NEW.output_kind_code IN ('normalized_text','diagnostic'))
      OR (p.method_code='manual_transcription' AND NEW.output_kind_code IN ('manual_transcript','diagnostic'))
    )
  ) THEN RAISE(ABORT,'processing method/output kind mismatch') END;
  SELECT CASE WHEN EXISTS(
    WITH RECURSIVE reachable(artifact_id) AS (
      SELECT NEW.artifact_id
      UNION
      SELECT o.artifact_id
      FROM reachable q
      JOIN atlas_processing_runs p ON p.input_artifact_id=q.artifact_id
      JOIN atlas_processing_outputs o ON o.processing_run_id=p.id
    )
    SELECT 1 FROM reachable q JOIN atlas_processing_runs p ON p.id=NEW.processing_run_id WHERE q.artifact_id=p.input_artifact_id
  ) THEN RAISE(ABORT,'processing lineage cycle') END;
  SELECT CASE WHEN NEW.recorded_by_principal_id=1 OR NOT EXISTS(
    SELECT 1 FROM atlas_processing_runs p
    JOIN atlas_artifacts a ON a.id=NEW.artifact_id
    JOIN atlas_evidence_bundle_receipts r ON r.id=NEW.evidence_bundle_receipt_id
    JOIN atlas_evidence_bundle_receipts artifact_receipt ON artifact_receipt.id=a.evidence_bundle_receipt_id
    WHERE p.id=NEW.processing_run_id AND p.outcome_code='succeeded' AND p.input_artifact_id<>NEW.artifact_id
      AND p.evidence_bundle_receipt_id=NEW.evidence_bundle_receipt_id AND p.recorded_by_principal_id=NEW.recorded_by_principal_id
      AND p.recorded_at=NEW.recorded_at AND p.started_at<=NEW.produced_at AND NEW.produced_at<=p.completed_at
      AND a.recorded_at<=NEW.recorded_at AND a.byte_layer_code='derived_output' AND NEW.recorded_at<=r.bundle_created_at
      AND (
        artifact_receipt.bundle_sequence<r.bundle_sequence
        OR NEW.produced_at<=a.recorded_at
        OR EXISTS(
          SELECT 1 FROM atlas_processing_outputs earlier_output
          JOIN atlas_processing_runs earlier_run ON earlier_run.id=earlier_output.processing_run_id
          JOIN atlas_evidence_bundle_receipts earlier_receipt ON earlier_receipt.id=earlier_run.evidence_bundle_receipt_id
          WHERE earlier_output.artifact_id=NEW.artifact_id
            AND (earlier_receipt.bundle_sequence<r.bundle_sequence OR (earlier_receipt.bundle_sequence=r.bundle_sequence AND earlier_run.run_ordinal<p.run_ordinal))
        )
      )
  ) THEN RAISE(ABORT,'invalid processing output lineage or chronology') END;
END;

CREATE TRIGGER atlas_candidate_occurrences_validate_insert BEFORE INSERT ON atlas_unverified_candidate_occurrences BEGIN
  SELECT CASE WHEN EXISTS(SELECT 1 FROM atlas_unverified_candidate_occurrences WHERE id=NEW.id OR candidate_record_code=NEW.candidate_record_code OR (NEW.corrects_candidate_occurrence_id IS NULL AND corrects_candidate_occurrence_id IS NULL AND candidate_chain_code=NEW.candidate_chain_code) OR (NEW.corrects_candidate_occurrence_id IS NOT NULL AND corrects_candidate_occurrence_id=NEW.corrects_candidate_occurrence_id)) THEN RAISE(ABORT,'candidate occurrence collision') END;
  SELECT CASE WHEN NEW.recorded_by_principal_id=1 OR NOT EXISTS(SELECT 1 FROM atlas_processing_outputs o JOIN atlas_processing_runs p ON p.id=o.processing_run_id JOIN atlas_evidence_bundle_receipts r ON r.id=NEW.evidence_bundle_receipt_id JOIN atlas_principals submitter ON submitter.id=NEW.recorded_by_principal_id WHERE o.id=NEW.processing_output_id AND o.processing_run_id=NEW.processing_run_id AND o.output_kind_code<>'diagnostic' AND p.outcome_code='succeeded' AND o.recorded_at<=NEW.recorded_at AND r.submitted_by_principal_id=NEW.recorded_by_principal_id AND submitter.created_at<=NEW.recorded_at AND NEW.recorded_at<=r.bundle_created_at) THEN RAISE(ABORT,'invalid candidate evidence lineage or attribution') END;
  SELECT CASE WHEN NEW.corrects_candidate_occurrence_id IS NULL AND EXISTS(SELECT 1 FROM atlas_unverified_candidate_occurrences WHERE candidate_chain_code=NEW.candidate_chain_code AND corrects_candidate_occurrence_id IS NULL) THEN RAISE(ABORT,'candidate chain already has a root') END;
  SELECT CASE WHEN NEW.corrects_candidate_occurrence_id IS NOT NULL AND NOT EXISTS(
    SELECT 1 FROM atlas_unverified_candidate_occurrences p
    JOIN atlas_evidence_bundle_receipts predecessor_receipt ON predecessor_receipt.id=p.evidence_bundle_receipt_id
    JOIN atlas_evidence_bundle_receipts successor_receipt ON successor_receipt.id=NEW.evidence_bundle_receipt_id
    WHERE p.id=NEW.corrects_candidate_occurrence_id AND p.candidate_chain_code=NEW.candidate_chain_code
      AND p.claim_type_code=NEW.claim_type_code AND p.recorded_at<NEW.recorded_at
      AND predecessor_receipt.bundle_sequence<=successor_receipt.bundle_sequence
      AND NOT EXISTS(SELECT 1 FROM atlas_unverified_candidate_occurrences s WHERE s.corrects_candidate_occurrence_id=p.id)
  ) THEN RAISE(ABORT,'invalid candidate correction successor') END;
END;

CREATE TRIGGER atlas_evidence_bundle_receipts_immutable_update BEFORE UPDATE ON atlas_evidence_bundle_receipts BEGIN SELECT RAISE(ABORT,'bundle receipts are immutable'); END;
CREATE TRIGGER atlas_evidence_bundle_receipts_immutable_delete BEFORE DELETE ON atlas_evidence_bundle_receipts BEGIN SELECT RAISE(ABORT,'bundle receipts are immutable'); END;
CREATE TRIGGER atlas_retrieval_locations_immutable_update BEFORE UPDATE ON atlas_retrieval_locations BEGIN SELECT RAISE(ABORT,'retrieval locations are immutable'); END;
CREATE TRIGGER atlas_retrieval_locations_immutable_delete BEFORE DELETE ON atlas_retrieval_locations BEGIN SELECT RAISE(ABORT,'retrieval locations are immutable'); END;
CREATE TRIGGER atlas_artifacts_immutable_update BEFORE UPDATE ON atlas_artifacts BEGIN SELECT RAISE(ABORT,'artifact identities are immutable'); END;
CREATE TRIGGER atlas_artifacts_immutable_delete BEFORE DELETE ON atlas_artifacts BEGIN SELECT RAISE(ABORT,'artifact identities are immutable'); END;
CREATE TRIGGER atlas_retrieval_events_immutable_update BEFORE UPDATE ON atlas_retrieval_events BEGIN SELECT RAISE(ABORT,'retrieval events are immutable'); END;
CREATE TRIGGER atlas_retrieval_events_immutable_delete BEFORE DELETE ON atlas_retrieval_events BEGIN SELECT RAISE(ABORT,'retrieval events are immutable'); END;
CREATE TRIGGER atlas_retrieval_redirects_immutable_update BEFORE UPDATE ON atlas_retrieval_redirects BEGIN SELECT RAISE(ABORT,'retrieval redirects are immutable'); END;
CREATE TRIGGER atlas_retrieval_redirects_immutable_delete BEFORE DELETE ON atlas_retrieval_redirects BEGIN SELECT RAISE(ABORT,'retrieval redirects are immutable'); END;
CREATE TRIGGER atlas_artifact_custody_events_immutable_update BEFORE UPDATE ON atlas_artifact_custody_events BEGIN SELECT RAISE(ABORT,'artifact custody events are immutable'); END;
CREATE TRIGGER atlas_artifact_custody_events_immutable_delete BEFORE DELETE ON atlas_artifact_custody_events BEGIN SELECT RAISE(ABORT,'artifact custody events are immutable'); END;
CREATE TRIGGER atlas_processing_runs_immutable_update BEFORE UPDATE ON atlas_processing_runs BEGIN SELECT RAISE(ABORT,'processing runs are immutable'); END;
CREATE TRIGGER atlas_processing_runs_immutable_delete BEFORE DELETE ON atlas_processing_runs BEGIN SELECT RAISE(ABORT,'processing runs are immutable'); END;
CREATE TRIGGER atlas_processing_outputs_immutable_update BEFORE UPDATE ON atlas_processing_outputs BEGIN SELECT RAISE(ABORT,'processing outputs are immutable'); END;
CREATE TRIGGER atlas_processing_outputs_immutable_delete BEFORE DELETE ON atlas_processing_outputs BEGIN SELECT RAISE(ABORT,'processing outputs are immutable'); END;
CREATE TRIGGER atlas_candidate_occurrences_immutable_update BEFORE UPDATE ON atlas_unverified_candidate_occurrences BEGIN SELECT RAISE(ABORT,'candidate occurrences are immutable'); END;
CREATE TRIGGER atlas_candidate_occurrences_immutable_delete BEFORE DELETE ON atlas_unverified_candidate_occurrences BEGIN SELECT RAISE(ABORT,'candidate occurrences are immutable'); END;
