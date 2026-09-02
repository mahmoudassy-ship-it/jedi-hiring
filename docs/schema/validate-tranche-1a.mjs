import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { fileURLToPath } from 'node:url'
import { applyMigrations } from '../../data/lib/migrations.mjs'
import { assertCanonicalBcp47 } from './bcp47.mjs'

const schemaDirectory = path.dirname(fileURLToPath(import.meta.url))
const projectDirectory = path.resolve(schemaDirectory, '../..')
const productionMigrationsDirectory = path.join(projectDirectory, 'data/migrations')
const proposalPath = path.join(schemaDirectory, 'tranche-1-foundations.proposed.sql')
const frozenNames = ['001_schema.sql', '002_reference_data.sql', '003_seed_eu_core.sql']
const legacyTables = ['jurisdictions','legal_instruments','requirements','hiring_stages','legal_lenses','actors','requirement_hiring_stages','requirement_legal_lenses','requirement_actors','requirement_relations','country_overlays','source_checks','requirement_search']
const expectedObjects = {
  index: ['atlas_jurisdiction_versions_bitemporal_idx','atlas_jurisdiction_versions_correction_idx','atlas_jurisdiction_versions_one_root_idx'],
  table: ['atlas_jurisdiction_versions','atlas_jurisdictions','atlas_languages','atlas_principals'],
  trigger: [
    'atlas_jurisdiction_versions_collision_guard','atlas_jurisdiction_versions_immutable_delete','atlas_jurisdiction_versions_immutable_update','atlas_jurisdiction_versions_validate_insert',
    'atlas_jurisdictions_collision_guard','atlas_jurisdictions_immutable_delete','atlas_jurisdictions_immutable_update',
    'atlas_languages_collision_guard','atlas_languages_immutable_delete','atlas_languages_immutable_update',
    'atlas_principals_attribution_guard','atlas_principals_bootstrap_guard','atlas_principals_collision_guard','atlas_principals_immutable_delete','atlas_principals_immutable_update',
  ],
}
const timestamp = '2026-09-02T12:00:00.000Z'

function tempDirectory(prefix) { return fs.mkdtempSync(path.join(os.tmpdir(), prefix)) }
function migrationDirectory(proposal = fs.readFileSync(proposalPath, 'utf8')) {
  const directory = tempDirectory('jedi-tranche-1a-migrations-')
  for (const name of frozenNames) fs.copyFileSync(path.join(productionMigrationsDirectory, name), path.join(directory, name))
  fs.writeFileSync(path.join(directory, '004_tranche_1a_foundations.sql'), proposal)
  return directory
}
function frozenDatabase() {
  const directory = tempDirectory('jedi-tranche-1a-frozen-'); const databasePath = path.join(directory, 'frozen.sqlite'); const database = new DatabaseSync(databasePath)
  database.exec('PRAGMA foreign_keys=ON; CREATE TABLE schema_migrations(name TEXT PRIMARY KEY, applied_at TEXT NOT NULL)')
  for (const [index,name] of frozenNames.entries()) { database.exec(fs.readFileSync(path.join(productionMigrationsDirectory,name),'utf8')); database.prepare('INSERT INTO schema_migrations VALUES(?,?)').run(name,`2026-01-0${index+1}T00:00:00.000Z`) }
  database.close(); return {directory,databasePath}
}
function writer(databasePath, recursiveTriggers = true) {
  const database = new DatabaseSync(databasePath)
  database.exec(`PRAGMA foreign_keys=ON; PRAGMA recursive_triggers=${recursiveTriggers ? 'ON' : 'OFF'}`)
  assert.equal(database.prepare('PRAGMA foreign_keys').get().foreign_keys,1)
  assert.equal(database.prepare('PRAGMA recursive_triggers').get().recursive_triggers,recursiveTriggers ? 1 : 0)
  return database
}
function digest(database,table) { const columns=database.prepare(`PRAGMA table_info(${table})`).all().map(x=>x.name); const rows=database.prepare(`SELECT * FROM "${table}" ORDER BY ${columns.map(x=>`"${x}"`).join(',')}`).all().map(x=>({...x})); return crypto.createHash('sha256').update(JSON.stringify(rows)).digest('hex') }
function digests(databasePath) { const database=new DatabaseSync(databasePath,{readOnly:true}); try{return Object.fromEntries(legacyTables.map(table=>[table,digest(database,table)]))}finally{database.close()} }
function reject(database,sql,values,pattern) { assert.throws(()=>database.prepare(sql).run(...values),pattern) }
function insertLanguage(database, tag, principalId=1) { assertCanonicalBcp47(tag); return database.prepare('INSERT INTO atlas_languages(language_code,recorded_by_principal_id,recorded_at)VALUES(?,?,?) RETURNING id').get(tag,principalId,timestamp).id }
function projection(database,jurisdictionId,languageId,effectiveAsOf,knownAt) {
  return database.prepare(`WITH eligible AS (
    SELECT * FROM atlas_jurisdiction_versions WHERE jurisdiction_id=? AND language_id=? AND effective_from<=? AND recorded_at<=?
  ), leaves AS (
    SELECT v.* FROM eligible v WHERE NOT EXISTS(SELECT 1 FROM eligible s WHERE s.corrects_jurisdiction_version_id=v.id)
  ) SELECT * FROM leaves WHERE record_kind_code<>'withdrawal' ORDER BY effective_from DESC, recorded_at DESC, id DESC LIMIT 1`
  ).get(jurisdictionId,languageId,effectiveAsOf,knownAt)
}

const proposal=fs.readFileSync(proposalPath,'utf8')
assert.doesNotMatch(proposal,/^\s*(BEGIN(?:\s+(?:IMMEDIATE|DEFERRED|EXCLUSIVE))?|COMMIT|ROLLBACK)\s*;/im)
assert.doesNotMatch(proposal,/sha256/i)
const cleanup=[]
try {
  const freshDir=tempDirectory('jedi-tranche-1a-fresh-'), freshPath=path.join(freshDir,'fresh.sqlite'), freshMigrations=migrationDirectory(); cleanup.push(freshDir,freshMigrations)
  assert.deepEqual(applyMigrations({databasePath:freshPath,migrationsDirectory:freshMigrations}).appliedNow,[...frozenNames,'004_tranche_1a_foundations.sql'])
  assert.deepEqual(applyMigrations({databasePath:freshPath,migrationsDirectory:freshMigrations}).appliedNow,[])

  const frozen=frozenDatabase(), upgradeMigrations=migrationDirectory(); cleanup.push(frozen.directory,upgradeMigrations)
  const before=digests(frozen.databasePath)
  assert.deepEqual(applyMigrations({databasePath:frozen.databasePath,migrationsDirectory:upgradeMigrations}).appliedNow,['004_tranche_1a_foundations.sql'])
  assert.deepEqual(digests(frozen.databasePath),before)

  let database=writer(frozen.databasePath)
  const objects=Object.fromEntries(['table','index','trigger'].map(type=>[type,database.prepare("SELECT name FROM sqlite_master WHERE type=? AND name LIKE 'atlas_%' ORDER BY name").all(type).map(x=>x.name)])); assert.deepEqual(objects,expectedObjects)
  assert.equal(database.prepare('PRAGMA integrity_check').get().integrity_check,'ok'); assert.deepEqual(database.prepare('PRAGMA foreign_key_check').all(),[])
  for(const table of expectedObjects.table) assert.equal(database.prepare(`SELECT count(*) count FROM ${table}`).get().count,0)

  reject(database,'INSERT INTO atlas_principals(id,principal_code,principal_kind_code,created_by_principal_id,created_at)VALUES(?,?,?,?,?)',[2,'not-bootstrap','human',2,timestamp],/first principal/)
  database.prepare('INSERT INTO atlas_principals(id,principal_code,principal_kind_code,created_by_principal_id,created_at)VALUES(1,?,?,1,?)').run('bootstrap','human',timestamp)
  reject(database,'INSERT INTO atlas_principals(id,principal_code,principal_kind_code,created_by_principal_id,created_at)VALUES(2,?,?,2,?)',['self','human',timestamp],/different recorded creator/)
  database.prepare('INSERT INTO atlas_principals(id,principal_code,principal_kind_code,created_by_principal_id,created_at)VALUES(2,?,?,1,?)').run('researcher','human',timestamp)
  for(const bad of [' ','bad code','nul\0code']) reject(database,'INSERT INTO atlas_principals(principal_code,principal_kind_code,created_by_principal_id,created_at)VALUES(?,?,1,?)',[bad,'human',timestamp],/CHECK/)
  reject(database,'INSERT INTO atlas_principals(principal_code,principal_kind_code,created_by_principal_id,created_at)VALUES(?,?,1,?)',['badtime','service','2026-09-02T25:00:00.000Z'],/CHECK/)

  for(const bad of ['-en','en-','en--US','1n','en\0US']) assert.throws(()=>assertCanonicalBcp47(bad),/language tag|BCP 47/)
  assert.throws(()=>assertCanonicalBcp47('en-us'),/noncanonical/); assert.equal(assertCanonicalBcp47('en-US'),'en-US')
  for(const bad of ['-en','en-','en--US','1n','en\0US']) reject(database,'INSERT INTO atlas_languages(language_code,recorded_by_principal_id,recorded_at)VALUES(?,?,?)',[bad,1,timestamp],/CHECK/)
  reject(database,'INSERT INTO atlas_languages(language_code,recorded_by_principal_id,recorded_at)VALUES(?,?,?)',['en-US',999,timestamp],/FOREIGN KEY/)
  const languageId=insertLanguage(database,'en-US')

  for(const bad of [' ','bad code','nul\0code']) reject(database,'INSERT INTO atlas_jurisdictions(jurisdiction_code,jurisdiction_kind_code,recorded_by_principal_id,recorded_at)VALUES(?,?,1,?)',[bad,'state',timestamp],/CHECK/)
  reject(database,'INSERT INTO atlas_jurisdictions(jurisdiction_code,jurisdiction_kind_code,recorded_by_principal_id,recorded_at)VALUES(?,?,999,?)',['bad-recorder','state',timestamp],/FOREIGN KEY/)
  const jurisdictionId=database.prepare('INSERT INTO atlas_jurisdictions(jurisdiction_code,jurisdiction_kind_code,recorded_by_principal_id,recorded_at)VALUES(?,?,1,?) RETURNING id').get('example','international',timestamp).id
  const otherJurisdictionId=database.prepare('INSERT INTO atlas_jurisdictions(jurisdiction_code,jurisdiction_kind_code,recorded_by_principal_id,recorded_at)VALUES(?,?,1,?) RETURNING id').get('other','state',timestamp).id
  const versionSql='INSERT INTO atlas_jurisdiction_versions(jurisdiction_id,language_id,effective_from,record_kind_code,name,description,corrects_jurisdiction_version_id,reason,recorded_by_principal_id,recorded_at)VALUES(?,?,?,?,?,?,?,?,?,?) RETURNING id'
  const insertVersion=database.prepare(versionSql)
  reject(database,versionSql,[jurisdictionId,languageId,'2026-01-01','assertion','Bad recorder',null,null,'Invalid recorder',999,'2026-01-02T00:00:00.000Z'],/FOREIGN KEY/)
  const root=insertVersion.get(jurisdictionId,languageId,'2026-01-01','assertion','Original',null,null,'Initial recording',1,'2026-01-02T00:00:00.000Z').id
  reject(database,versionSql,[jurisdictionId,languageId,'2026-01-01','assertion','Duplicate',null,null,'Duplicate root',1,'2026-01-03T00:00:00.000Z'],/initial assertion|UNIQUE/)
  reject(database,versionSql,[otherJurisdictionId,languageId,'2026-01-01','correction','Wrong',null,root,'Wrong subject',1,'2026-02-01T00:00:00.000Z'],/same effective point/)
  reject(database,versionSql,[jurisdictionId,languageId,'2026-01-01','correction','Too early',null,root,'Bad chronology',1,'2026-01-01T00:00:00.000Z'],/recorded later/)
  const correction=insertVersion.get(jurisdictionId,languageId,'2026-01-01','correction','Corrected',null,root,'Data correction',1,'2026-02-01T00:00:00.000Z').id
  assert.equal(projection(database,jurisdictionId,languageId,'2026-05-01','2026-01-15T00:00:00.000Z').name,'Original')
  assert.equal(projection(database,jurisdictionId,languageId,'2026-05-01','2026-03-01T00:00:00.000Z').name,'Corrected')
  insertVersion.get(jurisdictionId,languageId,'2026-06-01','assertion','Later change',null,null,'Substantive historical change',1,'2026-06-01T00:00:00.000Z')
  assert.equal(projection(database,jurisdictionId,languageId,'2026-07-01','2026-07-01T00:00:00.000Z').name,'Later change')
  insertVersion.get(jurisdictionId,languageId,'2026-01-01','withdrawal',null,null,correction,'Void erroneous effective point',1,'2026-04-01T00:00:00.000Z')
  assert.equal(projection(database,jurisdictionId,languageId,'2026-05-01','2026-05-01T00:00:00.000Z'),undefined)
  database.close()

  database=writer(frozen.databasePath,false)
  const replaceCases=[
    ["INSERT OR REPLACE INTO atlas_principals(id,principal_code,principal_kind_code,created_by_principal_id,created_at)VALUES(1,'bootstrap','service',1,?)",[timestamp]],
    ["INSERT OR REPLACE INTO atlas_languages(id,language_code,recorded_by_principal_id,recorded_at)VALUES(?, 'en-US',1,?)",[languageId,timestamp]],
    ["INSERT OR REPLACE INTO atlas_jurisdictions(id,jurisdiction_code,jurisdiction_kind_code,recorded_by_principal_id,recorded_at)VALUES(?, 'example','state',1,?)",[jurisdictionId,timestamp]],
    ["INSERT OR REPLACE INTO atlas_jurisdiction_versions(id,jurisdiction_id,language_id,effective_from,record_kind_code,name,reason,recorded_by_principal_id,recorded_at)VALUES(?,?,?,?,?,?,?,?,?)",[root,jurisdictionId,languageId,'2025-01-01','assertion','Replacement','Replace attempt',1,'2026-08-01T00:00:00.000Z']],
  ]
  for(const [sql,values] of replaceCases) reject(database,sql,values,/collision/)
  for(const table of expectedObjects.table) { reject(database,`UPDATE ${table} SET id=id WHERE id=(SELECT min(id) FROM ${table})`,[],/immutable/); reject(database,`DELETE FROM ${table} WHERE id=(SELECT min(id) FROM ${table})`,[],/immutable/) }
  database.close()

  const brokenDirectory=migrationDirectory(`${proposal}\nCREATE TABLE rollback_probe(id INTEGER PRIMARY KEY);\nINVALID SQL;\n`), brokenRoot=tempDirectory('jedi-tranche-1a-broken-'), brokenPath=path.join(brokenRoot,'broken.sqlite'); cleanup.push(brokenDirectory,brokenRoot)
  assert.throws(()=>applyMigrations({databasePath:brokenPath,migrationsDirectory:brokenDirectory}),/Migration 004_tranche_1a_foundations.sql failed/)
  const broken=new DatabaseSync(brokenPath,{readOnly:true}); assert.equal(broken.prepare("SELECT count(*) count FROM sqlite_master WHERE name LIKE 'atlas_%' OR name='rollback_probe'").get().count,0); assert.equal(broken.prepare("SELECT count(*) count FROM schema_migrations WHERE name='004_tranche_1a_foundations.sql'").get().count,0); broken.close()

  console.log(JSON.stringify({fresh_install:'passed',frozen_upgrade:'passed',no_op_rerun:'passed',migration_runner:'applyMigrations',legacy_digests_preserved:legacyTables.length,empty_seed_boundary:'passed',hash_fields:'deferred_no_input_surface',integrity_check:'ok',foreign_key_check:'clean',bitemporal_projection:'passed',recursive_triggers_off_replace_protection:'passed',broken_004_rollback:'passed',objects:Object.fromEntries(Object.entries(objects).map(([type,names])=>[type,names.length]))},null,2))
} finally { for(const directory of cleanup) fs.rmSync(directory,{recursive:true,force:true}) }
