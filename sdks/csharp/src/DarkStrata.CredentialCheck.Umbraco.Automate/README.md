# DarkStrata Credential Check for Umbraco Automate

Adds a **Compromised Credential Detected** trigger to [Umbraco Automate](https://docs.umbraco.com/umbraco-automate),
so editors can build their own response to a login or password change that uses stolen credentials on the canvas:
alert the security team in Slack, open a ticket, call a webhook, without writing a notification handler.

It fires whenever [DarkStrata.CredentialCheck.Umbraco](https://www.nuget.org/packages/DarkStrata.CredentialCheck.Umbraco)
publishes `CompromisedCredentialDetectedNotification`. Configure that package first.

## Requirements

| | Version |
|---|---|
| Umbraco CMS | 17.4 or later (17.x) |
| Umbraco Automate | 17.x |
| .NET | 10 |

## Install

```bash
dotnet add package DarkStrata.CredentialCheck.Umbraco.Automate
```

Restart the site. In **Automation**, add a trigger and pick **DarkStrata → Compromised Credential Detected**.

## Trigger settings

| Setting | Meaning |
|---|---|
| Sources | Comma-separated list of `MemberPassword`, `BackOfficePassword`, `MemberLogin`, `BackOfficeLogin`. Empty fires for all. |

## Trigger output

| Binding | Value |
|---|---|
| `${ trigger.source }` | Where the hit came from, as above. |
| `${ trigger.email }` | Email of the member or backoffice user. |
| `${ trigger.userId }` | Their Umbraco identity id, when known. |
| `${ trigger.detectedAt }` | UTC time of the hit. |

Automate records trigger output in its run history, so **emails and user ids are stored there**.
Apply the same retention and access rules you use for other personal data.

## Bursts

Hits for the same user and source start at most one run per 5-minute clock window (12:00–12:05,
12:05–12:10, ...), so a brute-force attempt against one account does not flood run history or your
alert channel. Two hits either side of a window boundary start two runs.

## If Automate is unavailable

Automate writes each trigger event to its database during the login. If that write fails or
stalls, DarkStrata.CredentialCheck.Umbraco logs the error and the login result stands; it stops
waiting after `NotificationTimeout` (default 5 seconds).
