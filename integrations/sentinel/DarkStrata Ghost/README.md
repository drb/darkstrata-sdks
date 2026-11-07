# DarkStrata Ghost solution for Microsoft Sentinel

Bring DarkStrata Ghost events into Microsoft Sentinel. A ghost is a honeytoken: a decoy identity that exists only to be stolen. You seed it somewhere you want to watch, and when DarkStrata finds it in a stealer log, breach or combolist, that place has leaked. Ghost sightings are high-fidelity by design, because nobody has a legitimate reason to hold a ghost's credentials.

> **Status: unreleased.** This solution has not been submitted to Content Hub yet.

## Contents

| Type | Name | What it does |
| --- | --- | --- |
| Data connector | DarkStrata Ghost (via Codeless Connector Framework) | Polls the Ghost event feed every 5 minutes into `DarkStrataGhostEvents_CL` |
| Analytics rule | DarkStrata Ghost - Identity ghost seen | Alerts on every IDENTITY ghost sighting |
| Analytics rule | DarkStrata Ghost - Ghost retired (tamper alarm) | Alerts when a ghost is retired |
| Analytics rule | DarkStrata Ghost - Proof of life missing | Alerts on the 2nd of the month when no `ghost.verified` arrived on the 1st |
| Analytics rule (template) | DarkStrata Ghost - Token / Decoy / Sensor ghost seen | For ghost kinds that are not available yet |
| Analytics rule (template) | Kerberos service ticket requested for a honey SPN | Domain controller 4769 for a honey SPN (Kerberoasting, T1558.003) |
| Analytics rule (template) | AS-REP requested without pre-authentication for a honey account | Domain controller 4768 without pre-auth (AS-REP roasting, T1558.004) |
| Workbook | DarkStrata Ghost | Events over time, sightings by kind and severity, latest sightings, tamper events, proof of life per ghost |
| ASIM parsers | `ASimAlertEventDarkStrataGhost`, `vimAlertEventDarkStrataGhost` | `ghost.seen` normalised to the ASIM Alert Event schema |

## Prerequisites

- A Microsoft Sentinel workspace, and Contributor (or Microsoft Sentinel Contributor plus Log Analytics Contributor) on its resource group.
- A DarkStrata API key with the `ghost:read` permission. Default API keys have it. Create one in the DarkStrata console.
- For the domain controller templates only: Windows Security events from your domain controllers in the `SecurityEvent` table (the *Windows Security Events via AMA* or *Security Events via Legacy Agent* connector), with *Audit Kerberos Service Ticket Operations* (4769) and *Audit Kerberos Authentication Service* (4768) enabled.

## Deploy

1. Install the **DarkStrata Ghost** solution from Content Hub (once published). Until then, build the package with Microsoft's [solution packaging tool](https://github.com/Azure/Azure-Sentinel/tree/master/Tools/Create-Azure-Sentinel-Solution/V3) against `Data/Solution_DarkStrataGhost.json`, and deploy the generated `Package/mainTemplate.json` to your workspace's resource group.
2. In Sentinel, open **Data connectors > DarkStrata Ghost (via Codeless Connector Framework)**, paste your API key and select **Connect**. The connector creates the `DarkStrataGhostEvents_CL` table, a data collection rule and the poller.
3. The first poll replays the last 30 days of events. After that, events arrive about a minute after DarkStrata records them (the feed holds back the newest minute so nothing is skipped), plus up to 5 minutes polling interval.
4. Open **Analytics > Rule templates**, filter by the DarkStrata Ghost solution and create rules from **Identity ghost seen**, **Ghost retired (tamper alarm)** and, once you have a ghost, **Proof of life missing**. Content Hub never enables rules for you; leave the other templates until you need them (see below).
5. Optionally, deploy the ASIM parsers (see [ASIM parsers](#asim-parsers)).

Self-test events (`is_test`) are ingested so you can check the pipeline end to end; every rule and the ASIM parsers exclude them, and the workbook hides them unless you choose **Include**.

## Table schema: `DarkStrataGhostEvents_CL`

One row per event. `TimeGenerated` is the ingestion time, so scheduled rules see each event once even when it was recorded earlier (for example in the first-poll replay).

| Column | Type | Source | Notes |
| --- | --- | --- | --- |
| TimeGenerated | datetime | ingestion time | |
| SchemaVersion | int | `schema_version` | `1` |
| EventId | string | `event_id` | UUID |
| Seq | long | `seq` | Feed cursor |
| EventType | string | `event_type` | `ghost.seen`, `ghost.deployed`, `ghost.retired`, `ghost.verified` |
| Kind | string | `kind` | `IDENTITY` today; `TOKEN`, `DECOY`, `SENSOR` later |
| Subtype | string | `subtype` | `EXACT_PAIR`, `EMAIL_OTHER_PASSWORD`, `EMAIL_ONLY` |
| Severity | string | `severity` | `INFO` to `CRITICAL` |
| IsTest | bool | `is_test` | Self-test event |
| ObservedAt | datetime | `observed_at` | When the leak was observed, if known |
| ReceivedAt | datetime | `received_at` | When DarkStrata recorded the event |
| GhostId | string | `ghost.id` | |
| GhostLabel | string | `ghost.label` | Customer-written: untrusted |
| GhostSeedUrl | string | `ghost.seed_url` | |
| GhostMode | string | `ghost.mode` | `asset` or `pool` |
| GhostEmail | string | `ghost.email` | `ghost.seen` only |
| GhostDisplayName | string | `ghost.display_name` | `ghost.seen` only |
| MatchKind | string | `match.kind` | |
| MatchSource | string | `match.source` | `STEALER_LOG`, `BREACH`, `COMBOLIST` |
| CorpusName | string | `match.corpus_name` | Leaked text: untrusted |
| RowIngestedAt | datetime | `match.row_ingested_at` | |
| MatchProvenance | dynamic | `match.provenance` | Leaked text: untrusted |
| Incident | dynamic | `incident` | Reserved (null) |
| MitreAttackVersion | string | `mitre.attack_version` | |
| MitreDomain | string | `mitre.domain` | `enterprise-attack` |
| MitreTechniques | dynamic | `mitre.techniques` | `[{id, name, parent_name, tactic_ids, basis}]` |
| MitreSoftware | dynamic | `mitre.software` | |
| RetiredById | string | `retired_by.id` | `ghost.retired` only |
| RetiredByName | string | `retired_by.name` | `ghost.retired` only |
| RetiredReason | string | `reason` | `asset_deleted`, or empty for a manual retire |
| VerifiedArmed | boolean | `verification.armed` | `ghost.verified` only (always true) |
| LastCheckedAt | datetime | `verification.last_checked_at` | `ghost.verified` only: last finished check of the ghost's domain |
| LastTestAt | datetime | `verification.last_test_at` | `ghost.verified` only: last self-test alert |
| ConsoleUrl | string | `console_url` | Link to the ghost in the DarkStrata console |

`GhostLabel`, `CorpusName` and `MatchProvenance` are written by your users or come from the leak itself. Treat them as untrusted text: display them, never act on them in automation.

## Analytics rules

The sighting and tamper rules run every 15 minutes, raise one alert per event, exclude self-tests and link each alert to the ghost in the DarkStrata console (`AlertLink`).

- **Identity ghost seen** (High). Fires on `ghost.seen` for `IDENTITY` ghosts. Alert severity comes from the event (`INFO` to Informational, `LOW` to Low, `MEDIUM` to Medium, `HIGH` and `CRITICAL` to High). Tactics come from the event's `mitre.techniques[].tactic_ids` (today TA0043, Reconnaissance; techniques T1589.001 for a password match and T1589.002 for an email-only match). Maps the ghost address to an Account entity. The alert name and description carry the ghost label and corpus name.
- **Ghost retired (tamper alarm)** (Medium, Defense Evasion, T1562). Retiring a ghost switches that tripwire off, so check that whoever retired it meant to. `RetiredReason` is `asset_deleted` when the ghost went because its domain was deleted from DarkStrata.
- **Proof of life missing** (Medium, Defense Evasion, T1562). DarkStrata sends `ghost.verified` on the 1st of each month for every armed ghost (domain enabled, verified and checked in the last 48 hours). An unarmed ghost gets none. The rule runs daily, acts only on the 2nd and raises one alert when no `ghost.verified` has arrived since the 1st, which also catches a stopped connector. Analytics rules look back at most 14 days, so it cannot check each ghost; the workbook's **Proof of life per ghost** table does.
- **Token / Decoy / Sensor ghost seen**. Templates for ghost kinds DarkStrata has not shipped yet. They match nothing until those kinds exist, and their tactics and techniques are provisional; each alert takes its real tactics from the event.

Sentinel's tactic list has no Stealth or Defense Impairment (both new in ATT&CK v20), so the rules map TA0005 and TA0112 to `DefenseEvasion`. The full mapping is in each rule's query.

### Domain controller honey-account rules

These are templates for a later Ghost phase: you create the honey accounts in Active Directory yourself, then enable the rules.

1. Create the honey accounts. Never use them, and give them long random passwords.
   - **Honey SPN** (Kerberoasting bait): a user account with a plausible service principal name, for example `MSSQLSvc/sql-legacy.corp.example:1433`.
   - **AS-REP honey account** (AS-REP roasting bait): a user account with *Do not require Kerberos preauthentication* set.
2. Create a Sentinel watchlist with alias **`DarkStrataHoneyAccounts`**, search key `AccountName`:

   ```csv
   AccountName,Type,Notes
   svc_sql_legacy,SPN,Honey SPN
   backup_admin_old,ASREP,AS-REP honey account
   ```

   `AccountName` is the sAMAccountName. `Type` is `SPN` or `ASREP`.
3. Create rules from **Kerberos service ticket requested for a honey SPN** (4769, T1558.003, Credential Access) and **AS-REP requested without pre-authentication for a honey account** (4768 with `PreAuthType` 0, T1558.004, Credential Access). Both are High and map the requesting account, client IP and domain controller to entities.

Nobody has a reason to request a ticket for these accounts, so any hit is worth an investigation.

## Workbook

**DarkStrata Ghost** shows ghost events over time by event type, sightings by kind and severity, the latest sightings (label, corpus, match kind and source, console link) tamper events (ghosts retired) and proof of life per ghost over a fixed 90 days (a ghost not retired and not verified in 33 days shows as **Not armed**). A toggle includes or excludes self-test events.

## ASIM parsers

`Parsers/ASimAlertEventDarkStrataGhost.yaml` and `Parsers/vimAlertEventDarkStrataGhost.yaml` normalise `ghost.seen` to the [ASIM Alert Event schema](https://aka.ms/ASimAlertEventDoc), including `AttackTactics` (ATT&CK names, for example `Reconnaissance`) and `AttackTechniques` (for example `Credentials (T1589.001)`). They are in the standard ASIM parser format, for submission to the Azure-Sentinel repository's `Parsers/ASimAlertEvent/Parsers/` folder so they join `_Im_AlertEvent`. Until then, save each `ParserQuery` as a workspace function named after its `ParserName`.

There is no ASIM Authentication parser: a ghost sighting is a credential found in leaked data, not a sign-in, so it does not fit the Authentication schema. NetworkSession, WebSession and Dns parsers will come with the sensor and token ghost kinds that produce those events.

## Data connector details

The connector is a Codeless Connector Framework `RestApiPoller`:

- `GET https://api.darkstrata.io/v1/ghosts/events?include_test=true&limit=100`, header `X-Api-Key: <key>`.
- `PersistentToken` paging: the connector sends `cursor=<next_cursor>` from the previous response, keeps paging while `has_more` is true, and keeps the last cursor between polls, so each event is fetched once. With nothing new, the feed echoes the cursor back.
- The data collection rule maps the JSON envelope to the typed columns above.

## Development

From `integrations/sentinel/`, run `npm ci && npm run validate`. It parses every JSON and YAML file, compiles every KQL query (rules, parsers, workbook, connector sample queries and the DCR transform) with Microsoft's Kusto.Language against the table schema, checks that the DCR transform outputs exactly the table's columns and uses only functions DCR transforms support, and checks rule tactics, techniques, entity mappings, custom details and alert-detail placeholders.

## Support

Email [support@darkstrata.io](mailto:support@darkstrata.io).
