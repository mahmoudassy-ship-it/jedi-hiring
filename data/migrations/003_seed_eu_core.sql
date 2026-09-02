INSERT INTO requirements (
  id, slug, instrument_id, title, plain_summary, source_locator, legal_effect, status,
  effective_from, effective_note, compliance_action, escalation_trigger,
  review_status, is_generated, last_reviewed_on
) VALUES
  (
    1, 'racial-ethnic-origin-discrimination', 1,
    'Do not discriminate because of racial or ethnic origin',
    'Recruitment criteria and practices must not directly or indirectly disadvantage people because of racial or ethnic origin unless a narrowly defined legal justification applies.',
    'Articles 2–5', 'prohibited', 'current', NULL,
    'Applied through national implementing law.',
    'Review job requirements, outreach, assessment outcomes, and selection records for direct and indirect discrimination.',
    'A criterion or outcome disproportionately excludes a racial or ethnic group, or a preference is proposed.',
    'research_only', 0, '2026-09-02'
  ),
  (
    2, 'employment-protected-grounds-discrimination', 2,
    'Do not discriminate on religion, belief, disability, age, or sexual orientation',
    'Access to employment, selection criteria, and recruitment conditions must comply with equal-treatment rules for the directive’s protected grounds.',
    'Articles 1–4', 'prohibited', 'current', NULL,
    'Applied through national implementing law; national protected grounds are often broader.',
    'Test every criterion for job relevance, legitimate aim, necessity, and proportionality; document any occupational requirement.',
    'A protected characteristic influences targeting, eligibility, scoring, or a selection preference.',
    'research_only', 0, '2026-09-02'
  ),
  (
    3, 'reasonable-accommodation-recruitment', 2,
    'Provide reasonable accommodation during recruitment',
    'Employers must take appropriate measures so a person with a disability can access and participate in employment and training unless this would impose a disproportionate burden.',
    'Article 5', 'required', 'current', NULL,
    'The duty reaches applications, tests, interviews, and other access-to-employment steps.',
    'Offer an accessible accommodation route, assess requests individually, and provide an equivalent alternative to inaccessible assessments.',
    'An applicant requests an adjustment, or a mandatory method creates a disability-related barrier.',
    'research_only', 0, '2026-09-02'
  ),
  (
    4, 'sex-pregnancy-maternity-equality', 3,
    'Protect sex equality, pregnancy, and maternity in recruitment',
    'Recruitment and access to employment must not discriminate on sex, including pregnancy and maternity protections developed in EU law.',
    'Articles 2, 14–19', 'prohibited', 'current', NULL,
    'Applied through national implementing law and interpreted through CJEU case law.',
    'Use objective selection and pay criteria; exclude pregnancy, maternity, and sex-based assumptions from decisions.',
    'Questions, scoring, or decisions involve pregnancy, caring assumptions, sex, or an automatic preference.',
    'research_only', 0, '2026-09-02'
  ),
  (
    5, 'positive-action-conditions', 2,
    'Treat positive action as conditional, not automatic permission',
    'EU equality law permits specific measures to prevent or compensate disadvantage, but the legal basis, evidence, proportionality, and form of preference depend on the ground and national law.',
    'Article 7; compare Directive 2000/43/EC Article 5 and Directive 2006/54/EC Article 3',
    'permitted_with_conditions', 'current', NULL,
    'Automatic or unconditional candidate preference is especially sensitive.',
    'Document the disadvantage, aim, legal basis, proportionality, individual assessment, duration, and review method before implementation.',
    'Reserved places, quotas, tie-breakers, or protected-characteristic preferences are proposed.',
    'local_validation_needed', 0, '2026-09-02'
  ),
  (
    6, 'gdpr-recruitment-principles', 4,
    'Apply GDPR principles to candidate data',
    'Candidate data must be processed lawfully, fairly, transparently, for defined purposes, in a necessary and proportionate way, and retained no longer than justified.',
    'Articles 5, 6, 12–14, 25 and 32', 'required', 'current', '2018-05-25',
    'Applies across sourcing, applications, assessments, references, talent pools, checks, and retention.',
    'Map purposes and legal bases, minimize fields and access, give candidate notices, secure the data, and define deletion schedules.',
    'New data sources, reuse, international transfers, long retention, or a vendor’s independent purposes are proposed.',
    'research_only', 0, '2026-09-02'
  ),
  (
    7, 'gdpr-sensitive-criminal-data', 4,
    'Use sensitive and criminal-record data only with specific authority',
    'Special-category data needs both an Article 6 basis and an Article 9 condition. Criminal-conviction data has separate Article 10 restrictions. Inclusion aims alone do not create authority.',
    'Articles 6, 9 and 10', 'permitted_with_conditions', 'current', '2018-05-25',
    'Employment consent may not be freely given; Member State law is central.',
    'Identify the precise legal authority, necessity, safeguards, access boundaries, reporting thresholds, and deletion rule before collection.',
    'Equality monitoring, health data, biometrics, religion, trade-union data, sexual orientation, or criminal checks are involved.',
    'local_validation_needed', 0, '2026-09-02'
  ),
  (
    8, 'gdpr-solely-automated-decisions', 4,
    'Restrict solely automated significant hiring decisions',
    'A person has the right not to be subject to a solely automated decision, including profiling, that produces legal or similarly significant effects unless a narrow exception and safeguards apply.',
    'Article 22; Recital 71', 'prohibited', 'current', '2018-05-25',
    'A nominal human click does not necessarily amount to meaningful intervention.',
    'Identify decision points, preserve genuine human authority and competence, explain the process, and provide intervention and contest routes where required.',
    'A system automatically rejects, ranks decisively, or makes a recommendation that reviewers normally rubber-stamp.',
    'research_only', 0, '2026-09-02'
  ),
  (
    9, 'gdpr-dpia-recruitment-profiling', 4,
    'Run a DPIA when recruitment processing is likely high risk',
    'A data protection impact assessment is required before processing likely to create high risk, including certain systematic and extensive evaluations, profiling, or sensitive-data uses.',
    'Article 35', 'required', 'current', '2018-05-25',
    'Supervisory-authority lists and national employment context affect the trigger.',
    'Screen the project before procurement or deployment; document necessity, proportionality, risks, safeguards, consultation, and residual risk.',
    'Large-scale scoring, novel monitoring, sensitive data, vulnerable people, or combined data sources are planned.',
    'local_validation_needed', 0, '2026-09-02'
  ),
  (
    10, 'ai-act-prohibited-hiring-practices', 5,
    'Screen hiring tools for prohibited AI practices',
    'The AI Act prohibits selected practices relevant to work, including workplace emotion inference except for medical or safety reasons and certain sensitive biometric categorisation.',
    'Article 5', 'prohibited', 'current', '2025-02-02',
    'Application to a particular candidate context requires facts and current guidance.',
    'Inventory biometric, video, voice, personality, affect, manipulation, and categorisation features before any trial or purchase.',
    'A vendor claims to infer emotion, personality, protected traits, trustworthiness, or vulnerability from biometric or behavioural signals.',
    'research_only', 0, '2026-09-02'
  ),
  (
    11, 'ai-literacy', 5,
    'Support AI literacy for people operating hiring AI',
    'Providers and deployers must take context-sensitive measures supporting AI literacy for staff and others operating or using AI systems on their behalf.',
    'Article 4, as amended', 'required', 'current', '2025-02-02',
    'The 2026 amendment changed the wording; use the current consolidated text.',
    'Train each role on the system’s purpose, limits, affected groups, oversight, escalation, and applicable data and equality duties.',
    'People can use or override a hiring AI system without role-specific training or authority.',
    'research_only', 0, '2026-09-02'
  ),
  (
    12, 'ai-candidate-interaction-transparency', 5,
    'Disclose direct interaction with an AI system where Article 50 applies',
    'People interacting directly with specified AI systems must be informed that they are interacting with AI unless this is obvious from the circumstances and context.',
    'Article 50', 'required', 'current', '2026-08-02',
    'Separate this disclosure from GDPR transparency and later high-risk-system notices.',
    'Place a clear, timely disclosure in candidate chat, interview, or assistance flows and preserve an accessible non-AI route where appropriate.',
    'A chatbot, conversational assessment, or automated interview interacts directly with candidates.',
    'research_only', 0, '2026-09-02'
  ),
  (
    13, 'ai-employment-high-risk-regime', 5,
    'Prepare Annex III employment AI for the high-risk regime',
    'AI used to target job adverts, analyse or filter applications, or evaluate candidates is generally an Annex III employment use case, subject to classification details and limited exclusions.',
    'Article 6; Annex III point 4(a); deployer duties in Article 26',
    'required', 'upcoming', '2027-12-02',
    'The 2026 AI Omnibus moved the applicable high-risk requirements for Annex III systems to 2 December 2027.',
    'Classify the use case, map provider and deployer roles, obtain documentation, define human oversight, validate input data, preserve logs, monitor outcomes, and prepare required notices.',
    'AI materially influences targeting, screening, assessment, or selection, or the employer modifies or rebrands the system.',
    'research_only', 0, '2026-09-02'
  ),
  (
    14, 'pay-transparency-before-employment', 7,
    'Provide transparent, gender-neutral pay information before employment',
    'Applicants must receive the initial pay or range early enough for informed negotiation; employers must not ask pay history and must use gender-neutral vacancy titles and non-discriminatory recruitment.',
    'Articles 5 and 8', 'required', 'country_transposition', '2026-06-07',
    'The directive’s transposition deadline has passed; check the actual national rule, including whether the range must appear in the advert.',
    'Set an objective range before publication, communicate it by the national deadline, remove pay-history questions, and make the information accessible.',
    'The country, employer size, communication timing, or permitted range format is unclear.',
    'local_validation_needed', 0, '2026-09-02'
  ),
  (
    15, 'dsa-sensitive-ad-profiling', 8,
    'Do not deliver platform ads using special-category profiling',
    'Online platforms must identify advertisements, disclose main targeting parameters, and must not present ads based on profiling that uses GDPR special-category data.',
    'Article 26', 'prohibited', 'current', '2024-02-17',
    'The direct DSA duty primarily falls on the platform; employers still face equality, GDPR, and AI Act questions.',
    'Review audience instructions and delivery reports, prohibit sensitive-category targeting, and require platform transparency in vendor terms.',
    'A recruitment campaign uses inferred protected traits, lookalike audiences, exclusions, or opaque automated delivery.',
    'research_only', 0, '2026-09-02'
  ),
  (
    16, 'worker-information-consultation', 9,
    'Check worker information and consultation before organisational change',
    'EU law establishes minimum employee information and consultation rights, while national works-council, co-determination, and collective-agreement rules may require earlier or stronger participation.',
    'Articles 1–4', 'country_review', 'current', NULL,
    'Thresholds and procedures are implemented nationally.',
    'Map affected entities and workers, consult local collective rules before procurement or deployment, and distinguish information from genuine consultation.',
    'Hiring technology changes work organisation, monitoring, roles, or contractual relations, or a works council is present.',
    'local_validation_needed', 0, '2026-09-02'
  ),
  (
    17, 'platform-work-algorithmic-management', 10,
    'Apply the platform-work algorithmic-management overlay where relevant',
    'Digital labour platforms face specific rules on employment status and automated monitoring or decision systems, including data limits, transparency, human oversight, review, and worker involvement.',
    'Chapters II and III', 'required', 'upcoming', '2026-12-02',
    'Member States must transpose the directive by 2 December 2026.',
    'Identify platform-work scope, track national transposition, map automated decisions from recruitment onward, and build human review and representative involvement.',
    'Work is organised through a digital labour platform, an intermediary is used, or worker status is contested.',
    'local_validation_needed', 0, '2026-09-02'
  ),
  (
    18, 'eu-worker-nationality-equality', 11,
    'Do not discriminate against EU workers because of nationality',
    'EU workers have equal access to employment across Member States, including recruitment procedures and vacancy advertising, subject to limited lawful exceptions.',
    'Articles 1–6', 'prohibited', 'current', NULL,
    'Language requirements must be justified by the nature of the post; third-country immigration rules are separate.',
    'Separate right-to-work verification from nationality preferences and document why any language or residence condition is necessary.',
    'Eligibility, advertising, language, residence, or recruitment procedure differs by nationality.',
    'research_only', 0, '2026-09-02'
  ),
  (
    19, 'public-recruitment-web-accessibility', 12,
    'Make covered public-sector recruitment websites accessible',
    'Public-sector websites and mobile applications within scope must meet accessibility requirements and provide an accessibility statement and feedback mechanism.',
    'Articles 4 and 7', 'country_review', 'current', NULL,
    'National implementation and scope exceptions must be checked; this is separate from reasonable accommodation.',
    'Include recruitment portals in accessibility governance, testing, statements, feedback, procurement, and remediation processes.',
    'A public employer or covered public-sector body operates the application portal.',
    'local_validation_needed', 0, '2026-09-02'
  ),
  (
    20, 'separate-equality-monitoring-data', 4,
    'Separate equality monitoring from candidate selection',
    'Using protected-characteristic data to measure disparity and using it to select a person are different processing purposes with different legal risks and access needs.',
    'Articles 5, 6 and 9', 'permitted_with_conditions', 'current', '2018-05-25',
    'A monitoring objective does not by itself provide an Article 9 condition.',
    'Use a documented basis, voluntary and transparent collection where lawful, strict access separation, aggregation thresholds, purpose controls, and a deletion schedule.',
    'Selectors can see monitoring data, small groups can be re-identified, or monitoring data may be reused operationally.',
    'local_validation_needed', 0, '2026-09-02'
  );

INSERT INTO requirement_hiring_stages (requirement_id, hiring_stage_id) VALUES
  (1,1),(1,2),(1,3),(1,4),(1,5),(1,6),(1,8),
  (2,1),(2,2),(2,3),(2,4),(2,5),(2,6),(2,8),
  (3,1),(3,3),(3,4),(3,5),(3,6),(3,7),
  (4,1),(4,2),(4,3),(4,4),(4,5),(4,6),(4,8),
  (5,1),(5,2),(5,4),(5,6),(5,8),
  (6,2),(6,3),(6,4),(6,5),(6,6),(6,7),(6,8),
  (7,3),(7,4),(7,5),(7,7),(7,8),
  (8,4),(8,6),(8,8),
  (9,2),(9,3),(9,4),(9,6),(9,8),
  (10,4),(10,5),
  (11,2),(11,3),(11,4),(11,5),(11,6),(11,7),(11,8),
  (12,2),(12,3),(12,4),(12,5),(12,6),
  (13,2),(13,4),(13,5),(13,6),
  (14,1),(14,2),(14,5),(14,6),
  (15,2),
  (16,1),(16,4),(16,8),
  (17,2),(17,3),(17,4),(17,6),(17,8),
  (18,2),(18,3),(18,6),(18,7),
  (19,2),(19,3),(19,4),(19,5),
  (20,3),(20,8);

INSERT INTO requirement_legal_lenses (requirement_id, legal_lens_id) VALUES
  (1,1),(1,9),
  (2,1),(2,9),
  (3,1),(3,6),
  (4,1),(4,4),(4,9),
  (5,1),(5,9),
  (6,2),(6,9),
  (7,1),(7,2),(7,9),
  (8,2),(8,3),(8,9),
  (9,2),(9,3),
  (10,1),(10,3),
  (11,3),
  (12,2),(12,3),
  (13,1),(13,2),(13,3),(13,8),
  (14,1),(14,4),(14,6),
  (15,1),(15,2),(15,8),
  (16,3),(16,5),
  (17,2),(17,3),(17,5),(17,8),
  (18,1),(18,7),
  (19,6),
  (20,1),(20,2),(20,9);

INSERT INTO requirement_actors (requirement_id, actor_id) VALUES
  (1,1),(1,2),
  (2,1),(2,2),
  (3,1),(3,2),(3,6),
  (4,1),(4,2),
  (5,1),(5,2),
  (6,1),(6,3),(6,6),
  (7,1),(7,3),(7,6),
  (8,1),(8,3),(8,4),(8,6),
  (9,1),(9,3),(9,4),(9,6),
  (10,1),(10,4),(10,5),(10,6),
  (11,1),(11,4),(11,5),
  (12,1),(12,4),(12,5),(12,6),
  (13,1),(13,4),(13,5),(13,6),
  (14,1),(14,2),
  (15,1),(15,6),(15,7),
  (16,1),(16,8),
  (17,1),(17,7),(17,8),
  (18,1),(18,2),
  (19,9),
  (20,1),(20,2),(20,3);

INSERT INTO requirement_relations (
  from_requirement_id, to_requirement_id, relation_type, notes
) VALUES
  (5, 1, 'compare_with', 'Positive action must remain within racial-equality safeguards and national law.'),
  (5, 2, 'compare_with', 'The permitted positive-action framework varies by protected ground and national implementation.'),
  (8, 13, 'overlaps', 'GDPR automated-decision rules remain applicable before and after the AI Act high-risk regime.'),
  (9, 13, 'overlaps', 'A GDPR DPIA and AI Act deployment assessment have different triggers and should be coordinated.'),
  (10, 13, 'limits', 'A prohibited practice cannot be made lawful by high-risk compliance.'),
  (13, 2, 'overlaps', 'AI Act conformity does not legalise discriminatory recruitment.'),
  (13, 6, 'overlaps', 'AI Act and GDPR roles and duties must be mapped independently.'),
  (14, 4, 'implements', 'Pay transparency strengthens the practical enforcement of sex-equality and equal-pay rights.'),
  (15, 1, 'overlaps', 'Platform ad delivery can create separate equality-law exposure.'),
  (16, 13, 'overlaps', 'AI Act worker information does not replace national consultation rights.'),
  (17, 13, 'compare_with', 'Platform-work algorithmic rules and the horizontal AI Act have different scopes and actors.'),
  (20, 7, 'depends_on', 'Equality monitoring requires a specific GDPR legal basis and condition where special-category data is used.');
