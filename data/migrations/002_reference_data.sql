INSERT INTO jurisdictions (id, code, name, level, parent_id, notes) VALUES
  (1, 'EU', 'European Union', 'eu', NULL, 'EU-level baseline; Member State implementation and enforcement still require local review.');

INSERT INTO hiring_stages (id, slug, name, position) VALUES
  (1, 'role-design', 'Role design', 1),
  (2, 'advertising-sourcing', 'Advertising & sourcing', 2),
  (3, 'application-data', 'Application & data collection', 3),
  (4, 'screening-assessment', 'Screening & assessment', 4),
  (5, 'interview-accommodation', 'Interview & accommodation', 5),
  (6, 'decision-offer', 'Decision & offer', 6),
  (7, 'checks-onboarding', 'Checks & onboarding', 7),
  (8, 'monitoring-redress', 'Monitoring & redress', 8);

INSERT INTO legal_lenses (id, slug, name, position) VALUES
  (1, 'equality', 'Equality & positive action', 1),
  (2, 'privacy-data', 'Privacy & candidate data', 2),
  (3, 'ai-automation', 'AI & automation', 3),
  (4, 'pay-employment', 'Pay & employment', 4),
  (5, 'worker-voice', 'Worker voice', 5),
  (6, 'accessibility', 'Accessibility', 6),
  (7, 'mobility', 'Mobility & migration', 7),
  (8, 'platform-vendors', 'Platforms & vendors', 8),
  (9, 'remedies-evidence', 'Evidence & remedies', 9);

INSERT INTO actors (id, slug, name) VALUES
  (1, 'employer', 'Employer'),
  (2, 'hiring-team', 'Hiring team'),
  (3, 'data-controller', 'Data controller'),
  (4, 'ai-deployer', 'AI deployer'),
  (5, 'ai-provider', 'AI provider'),
  (6, 'recruitment-vendor', 'Recruitment vendor'),
  (7, 'online-platform', 'Online platform'),
  (8, 'worker-representatives', 'Worker representatives'),
  (9, 'public-employer', 'Public employer');

INSERT INTO legal_instruments (
  id, slug, title, short_title, citation, instrument_type, jurisdiction_id, status,
  official_url, adopted_on, applies_from, transposition_deadline, last_verified_on, notes
) VALUES
  (
    1,
    'racial-equality-directive',
    'Council Directive 2000/43/EC implementing the principle of equal treatment between persons irrespective of racial or ethnic origin',
    'Racial Equality Directive',
    'Directive 2000/43/EC',
    'directive', 1, 'in_force',
    'https://eur-lex.europa.eu/eli/dir/2000/43/oj/eng',
    '2000-06-29', NULL, '2003-07-19', '2026-09-02',
    'National implementing law may add protected grounds, procedures, and remedies.'
  ),
  (
    2,
    'employment-equality-directive',
    'Council Directive 2000/78/EC establishing a general framework for equal treatment in employment and occupation',
    'Employment Equality Directive',
    'Directive 2000/78/EC',
    'directive', 1, 'in_force',
    'https://eur-lex.europa.eu/eli/dir/2000/78/oj/eng',
    '2000-11-27', NULL, '2003-12-02', '2026-09-02',
    'Covers religion or belief, disability, age, and sexual orientation in employment and occupation.'
  ),
  (
    3,
    'gender-equality-directive',
    'Directive 2006/54/EC on equal opportunities and equal treatment of men and women in matters of employment and occupation',
    'Gender Equality Directive',
    'Directive 2006/54/EC',
    'directive', 1, 'in_force',
    'https://eur-lex.europa.eu/eli/dir/2006/54/oj/eng',
    '2006-07-05', NULL, '2008-08-15', '2026-09-02',
    'Includes access to employment, recruitment, pregnancy and maternity protections, harassment, and equal pay.'
  ),
  (
    4,
    'gdpr',
    'Regulation (EU) 2016/679 on the protection of natural persons with regard to the processing of personal data',
    'GDPR',
    'Regulation (EU) 2016/679',
    'regulation', 1, 'in_force',
    'https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng',
    '2016-04-27', '2018-05-25', NULL, '2026-09-02',
    'Member State employment-data rules under Article 88 can add important local requirements.'
  ),
  (
    5,
    'eu-ai-act',
    'Regulation (EU) 2024/1689 laying down harmonised rules on artificial intelligence',
    'EU AI Act',
    'Regulation (EU) 2024/1689',
    'regulation', 1, 'in_force',
    'https://eur-lex.europa.eu/eli/reg/2024/1689',
    '2024-06-13', '2026-08-02', NULL, '2026-09-02',
    'Use the current consolidated text because the 2026 AI Omnibus amended application dates and selected obligations.'
  ),
  (
    6,
    'ai-omnibus-2026',
    'Regulation (EU) 2026/1744 amending the Artificial Intelligence Act',
    'AI Omnibus 2026',
    'Regulation (EU) 2026/1744',
    'regulation', 1, 'in_force',
    'https://eur-lex.europa.eu/eli/reg/2026/1744/oj/eng',
    '2026-07-08', '2026-07-27', NULL, '2026-09-02',
    'Among other changes, moves Annex III high-risk employment requirements to 2 December 2027.'
  ),
  (
    7,
    'pay-transparency-directive',
    'Directive (EU) 2023/970 to strengthen the application of the principle of equal pay through pay transparency and enforcement mechanisms',
    'Pay Transparency Directive',
    'Directive (EU) 2023/970',
    'directive', 1, 'transposition',
    'https://eur-lex.europa.eu/eli/dir/2023/970/oj/eng',
    '2023-05-10', NULL, '2026-06-07', '2026-09-02',
    'The transposition deadline has passed; the operative national implementing law must be checked.'
  ),
  (
    8,
    'digital-services-act',
    'Regulation (EU) 2022/2065 on a Single Market For Digital Services',
    'Digital Services Act',
    'Regulation (EU) 2022/2065',
    'regulation', 1, 'in_force',
    'https://eur-lex.europa.eu/eli/reg/2022/2065/oj/eng',
    '2022-10-19', '2024-02-17', NULL, '2026-09-02',
    'The advertising duties primarily regulate online platforms; employers retain separate equality and GDPR duties.'
  ),
  (
    9,
    'employee-information-consultation-directive',
    'Directive 2002/14/EC establishing a general framework for informing and consulting employees',
    'Information & Consultation Directive',
    'Directive 2002/14/EC',
    'directive', 1, 'in_force',
    'https://eur-lex.europa.eu/eli/dir/2002/14/oj/eng',
    '2002-03-11', NULL, '2005-03-23', '2026-09-02',
    'National thresholds, co-determination law, collective agreements, and works-council powers can be stronger.'
  ),
  (
    10,
    'platform-work-directive',
    'Directive (EU) 2024/2831 on improving working conditions in platform work',
    'Platform Work Directive',
    'Directive (EU) 2024/2831',
    'directive', 1, 'transposition',
    'https://eur-lex.europa.eu/eli/dir/2024/2831/oj/eng',
    '2024-10-23', NULL, '2026-12-02', '2026-09-02',
    'A sector-specific overlay for digital labour platforms, including recruitment and algorithmic management.'
  ),
  (
    11,
    'free-movement-workers-regulation',
    'Regulation (EU) No 492/2011 on freedom of movement for workers within the Union',
    'Free Movement of Workers Regulation',
    'Regulation (EU) No 492/2011',
    'regulation', 1, 'in_force',
    'https://eur-lex.europa.eu/eli/reg/2011/492/oj/eng',
    '2011-04-05', NULL, NULL, '2026-09-02',
    'Nationality, race or ethnicity, and third-country immigration status are distinct legal questions.'
  ),
  (
    12,
    'web-accessibility-directive',
    'Directive (EU) 2016/2102 on the accessibility of the websites and mobile applications of public sector bodies',
    'Web Accessibility Directive',
    'Directive (EU) 2016/2102',
    'directive', 1, 'in_force',
    'https://eur-lex.europa.eu/eli/dir/2016/2102/oj/eng',
    '2016-10-26', NULL, '2018-09-23', '2026-09-02',
    'Relevant to public-employer recruitment portals; it is not a universal private career-site rule.'
  );

INSERT INTO source_checks (instrument_id, checked_on, check_status, notes)
SELECT id, '2026-09-02', 'current', 'Official source URL checked when the initial scaffold dataset was prepared.'
FROM legal_instruments;
