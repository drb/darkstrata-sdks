#!/usr/bin/env node
// Validates the DarkStrata Ghost Sentinel solution offline: JSON/YAML parse, KQL compiles against the
// table schema (Kusto.Language), DCR transform output matches the table, rule fields are well formed.
// Usage: npm ci && npm run validate
import { createRequire } from 'node:module';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
globalThis.Bridge = require('@kusto/language-service-next/bridge.js');
require('@kusto/language-service-next/Kusto.Language.Bridge.js');
const yaml = require('js-yaml');
const K = globalThis.Kusto.Language;

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', 'DarkStrata Ghost');
const CCF = join(ROOT, 'Data Connectors', 'DarkStrataGhost_CCF');
const SENTINEL_TACTICS = new Set(['Reconnaissance', 'ResourceDevelopment', 'InitialAccess', 'Execution', 'Persistence',
  'PrivilegeEscalation', 'DefenseEvasion', 'CredentialAccess', 'Discovery', 'LateralMovement', 'Collection',
  'Exfiltration', 'CommandAndControl', 'Impact', 'PreAttack', 'ImpairProcessControl', 'InhibitResponseFunction']);
const SEVERITIES = new Set(['Informational', 'Low', 'Medium', 'High']);
const TECHNIQUE_RE = /^T\d{4}(\.\d{3})?$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const RULE_KEYS = ['id', 'name', 'description', 'severity', 'requiredDataConnectors', 'queryFrequency', 'queryPeriod',
  'triggerOperator', 'triggerThreshold', 'tactics', 'relevantTechniques', 'query', 'version', 'kind'];
// Only the SecurityEvent columns the honey-account rules use
const SECURITY_EVENT = 'datatable(TimeGenerated:datetime, EventID:int, EventData:string, Computer:string, TargetUserName:string, TargetDomainName:string, IpAddress:string)[]';
const WATCHLIST = 'let _GetWatchlist = (alias: string) { datatable(SearchKey:string, Type:string)[] };';

const errors = [];
const fail = (where, msg) => errors.push(`${where}: ${msg}`);
const files = (dir, ext) => readdirSync(dir).filter((f) => f.endsWith(ext)).map((f) => join(dir, f));
const rel = (p) => p.slice(ROOT.length + 1);

function listOf(bridgeList) {
  const out = [];
  for (let i = 0; i < bridgeList.Count; i++) out.push(bridgeList.getItem(i));
  return out;
}

/** Compile KQL; report errors; return the result columns as {name: type} */
function analyse(where, text) {
  const code = K.KustoCode.ParseAndAnalyze(text, K.GlobalState.Default);
  for (const d of listOf(code.GetDiagnostics())) if (d.Severity === 'Error') fail(where, `KQL: ${d.Message}`);
  const cols = {};
  if (code.ResultType?.Columns) for (const c of listOf(code.ResultType.Columns)) cols[c.Name] = c.Type.Name;
  return cols;
}

const readJson = (p) => {
  try { return JSON.parse(readFileSync(p, 'utf8')); } catch (e) { fail(rel(p), `invalid JSON: ${e.message}`); return null; }
};
const readYaml = (p) => {
  try { return yaml.load(readFileSync(p, 'utf8')); } catch (e) { fail(rel(p), `invalid YAML: ${e.message}`); return null; }
};
const datatable = (cols) => `datatable(${cols.map((c) => `['${c.name}']:${c.type}`).join(', ')})[]`;

// ── JSON files ──
const allJson = [ROOT, CCF, join(ROOT, 'Data'), join(ROOT, 'Workbooks')].flatMap((d) => files(d, '.json'));
const json = Object.fromEntries(allJson.map((p) => [rel(p), readJson(p)]));

// ── Table and DCR ──
const table = json['Data Connectors/DarkStrataGhost_CCF/DarkStrataGhost_Table.json'];
const dcr = json['Data Connectors/DarkStrataGhost_CCF/DarkStrataGhost_DCR.json']?.[0];
const poller = json['Data Connectors/DarkStrataGhost_CCF/DarkStrataGhost_PollerConfig.json']?.[0];
const definition = json['Data Connectors/DarkStrataGhost_CCF/DarkStrataGhost_ConnectorDefinition.json'];
const tableCols = table.properties.schema.columns;
const GHOST_TABLE = `let DarkStrataGhostEvents_CL = ${datatable(tableCols)};`;

const [stream, decl] = Object.entries(dcr.properties.streamDeclarations)[0];
const flow = dcr.properties.dataFlows[0];
const out = analyse('DCR transformKql', `let source = ${datatable(decl.columns)};\n${flow.transformKql}`);
const want = Object.fromEntries(tableCols.map((c) => [c.name, c.type === 'boolean' ? 'bool' : c.type]));
for (const [n, t] of Object.entries(want)) if (out[n] !== t) fail('DCR transformKql', `column ${n}: table ${t}, transform ${out[n] ?? 'missing'}`);
for (const n of Object.keys(out)) if (!(n in want)) fail('DCR transformKql', `column ${n} not in table`);
// DCR transforms run a KQL subset (learn.microsoft.com/azure/azure-monitor/data-collection/data-collection-transformations-kql)
// ponytail: only the functions this transform needs; extend from that page when the transform grows
const DCR_FUNCTIONS = new Set(['now', 'tostring', 'toint', 'tolong', 'tobool', 'todatetime', 'parse_json', 'iif', 'case', 'isempty', 'isnotempty']);
for (const [, fn] of flow.transformKql.matchAll(/\b([a-z_]+)\(/g)) if (!DCR_FUNCTIONS.has(fn)) fail('DCR transformKql', `${fn}() is not supported in DCR transforms`);
if (flow.outputStream !==`Custom-${table.name}`) fail('DCR', `outputStream ${flow.outputStream} != Custom-${table.name}`);
if (!flow.streams.includes(stream)) fail('DCR', `dataFlow does not read ${stream}`);
if (poller.properties.dcrConfig.streamName !== stream) fail('PollerConfig', `streamName != ${stream}`);
if (poller.properties.dataType !== table.name) fail('PollerConfig', `dataType != ${table.name}`);
if (poller.properties.connectorDefinitionName !== definition.name) fail('PollerConfig', 'connectorDefinitionName mismatch');
if (definition.properties.connectorUiConfig.id !== definition.name) fail('ConnectorDefinition', 'id != name');
const uiParams = definition.properties.connectorUiConfig.instructionSteps.flatMap((s) => s.instructions).map((i) => i.parameters?.name);
for (const [, p] of JSON.stringify(poller).matchAll(/parameters\('(\w+)'\)/g)) if (!uiParams.includes(p)) fail('PollerConfig', `parameter ${p} has no UI input`);
for (const q of definition.properties.connectorUiConfig.sampleQueries) {
  analyse(`sample query "${q.description}"`, `${GHOST_TABLE}\n${q.query.replaceAll('{{graphQueriesTableName}}', table.name)}`);
}

// ── Analytics rules ──
const ids = new Set();
for (const p of files(join(ROOT, 'Analytic Rules'), '.yaml')) {
  const r = readYaml(p); const where = rel(p);
  if (!r) continue;
  for (const k of RULE_KEYS) if (!(k in r)) fail(where, `missing ${k}`);
  if (!UUID_RE.test(r.id)) fail(where, 'id is not a lower-case UUID');
  if (ids.has(r.id)) fail(where, 'duplicate id'); ids.add(r.id);
  if (!SEVERITIES.has(r.severity)) fail(where, `severity ${r.severity}`);
  for (const t of r.tactics ?? []) if (!SENTINEL_TACTICS.has(t)) fail(where, `tactic ${t}`);
  for (const t of r.relevantTechniques ?? []) if (!TECHNIQUE_RE.test(t)) fail(where, `technique ${t}`);
  const cols = analyse(where, `${GHOST_TABLE}\n${WATCHLIST}\nlet SecurityEvent = ${SECURITY_EVENT};\n${r.query}`);
  const used = [
    ...(r.entityMappings ?? []).flatMap((e) => e.fieldMappings.map((f) => f.columnName)),
    ...Object.values(r.customDetails ?? {}),
    ...['alertSeverityColumnName', 'alertTacticsColumnName'].map((k) => r.alertDetailsOverride?.[k]).filter(Boolean),
    ...(r.alertDetailsOverride?.alertDynamicProperties ?? []).map((d) => d.value),
  ];
  for (const fmt of ['alertDisplayNameFormat', 'alertDescriptionFormat']) {
    const ph = [...(r.alertDetailsOverride?.[fmt] ?? '').matchAll(/\{\{(\w+)\}\}/g)].map((m) => m[1]);
    if (ph.length > 3) fail(where, `${fmt} has ${ph.length} placeholders (max 3)`);
    used.push(...ph);
  }
  for (const c of used) if (!(c in cols)) fail(where, `column ${c} is not in the query output`);
  if (Object.keys(r.customDetails ?? {}).length > 20) fail(where, 'more than 20 customDetails');
  if ((r.entityMappings ?? []).some((e) => e.fieldMappings.length > 3)) fail(where, 'entity with more than 3 identifiers');
}

// ── ASIM parsers ──
for (const p of files(join(ROOT, 'Parsers'), '.yaml')) {
  const y = readYaml(p); const where = rel(p);
  if (!y) continue;
  for (const k of ['Parser', 'Normalization', 'ParserName', 'ParserParams', 'ParserQuery']) if (!(k in y)) fail(where, `missing ${k}`);
  const params = (y.ParserParams ?? []).map((x) => `let ${x.Name} = ${x.Default};`).join('\n');
  const cols = analyse(where, `${GHOST_TABLE}\n${params}\n${y.ParserQuery}`);
  for (const c of ['EventCount', 'EventStartTime', 'EventEndTime', 'EventType', 'EventUid', 'EventProduct', 'EventVendor',
    'EventSchema', 'EventSchemaVersion', 'AttackTactics', 'AttackTechniques', 'AlertName', 'Username']) {
    if (!(c in cols)) fail(where, `ASIM field ${c} missing from output`);
  }
}

// ── Workbook ──
const wb = json['Workbooks/DarkStrataGhost.json'];
const walk = (items) => items.flatMap((i) => (i.content?.items ? walk(i.content.items) : [i]));
for (const item of walk(wb.items)) {
  if (item.type !== 3) continue;
  analyse(`workbook ${item.name}`, `${GHOST_TABLE}\n${item.content.query.replaceAll('{IncludeTest}', 'true')}`);
}

// ── Solution manifest ──
const sol = json['Data/Solution_DarkStrataGhost.json'];
for (const key of ['Data Connectors', 'Analytic Rules', 'Workbooks', 'Parsers', 'Hunting Queries']) {
  for (const p of sol[key] ?? []) if (!existsSync(join(ROOT, '..', p))) fail('Solution', `${key}: ${p} does not exist`);
}
const listed = new Set(sol['Analytic Rules']);
for (const p of files(join(ROOT, 'Analytic Rules'), '.yaml')) if (!listed.has(`${sol.Name}/${rel(p)}`)) fail('Solution', `${rel(p)} not listed`);

if (errors.length) {
  console.error(errors.join('\n'));
  process.exit(1);
}
console.log(`OK: ${allJson.length} JSON files, ${ids.size} analytics rules, parsers, workbook and DCR transform validated`);
