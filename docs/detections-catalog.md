# Detections catalogue

The 28 rules, grouped by area. Each rule has a severity, a plain-language explanation, a fix, a
remediation action and framework mappings (MITRE ATT&CK, MITRE ATLAS, OWASP LLM where relevant, CIS
Controls and a Zero Trust principle). The tables below are rendered from `detections/rules.yaml` by the
CLI and checked in CI. Implementation: [detections](components/detections.md).

Areas:

* **Privilege and escalation paths** (codes P): standing admin rights, risky permissions, routes to crown
  jewels.
* **Foundational identity hygiene** (codes F): MFA, dormant accounts, legacy authentication, vault access
  model, SaaS admins.
* **AI agents, workload identities and secrets** (codes E): agent identities and tools, secrets and
  credentials, federated trust.

## Summary

<!-- output: rules -->
```text
code  id                               area          severity  ATT&CK                     ATLAS / OWASP LLM                    CIS
----  -------------------------------  ------------  --------  -------------------------  -----------------------------------  --------
P01   standing-privileged-role         privilege     high      T1078.004 T1098.003        -                                    5.4 6.8
P02   standing-azure-admin             privilege     high      T1078.004 T1098.003        -                                    5.4 6.8
P03   workload-subscription-privilege  privilege     high      T1078.004 T1552.005 T1651  -                                    5.5 6.8
P04   high-risk-app-permission         privilege     critical  T1098.003 T1550.001        -                                    6.8
P05   human-path-to-crown-jewel        privilege     critical  T1078.004 T1098.001 T1651  -                                    6.8 5.4
P06   guest-with-privilege             privilege     high      T1199 T1078.004            -                                    6.1 6.2
P07   external-app-with-privilege      privilege     high      T1199                      -                                    15.1 6.8
P08   risky-consent-grant              privilege     high      T1528 T1550.001            -                                    2.5 6.1
F01   no-mfa-registered                foundational  high      T1110.003 T1078.004        -                                    6.3 6.4
F02   privileged-without-enforced-mfa  foundational  critical  T1110.003 T1078.004        -                                    6.5
F03   dormant-account                  foundational  medium    T1078.004                  -                                    5.3
F04   emergency-account-weak-method    foundational  high      T1110 T1078.004            -                                    6.5
F05   legacy-auth-not-blocked          foundational  high      T1110.003                  -                                    6.3
F06   vault-legacy-access-policies     foundational  medium    T1555.006                  -                                    6.8 3.3
F07   saas-admin-outside-sso           foundational  high      T1078.003 T1078.004        -                                    5.4 6.7
E01   long-lived-app-secret            emerging      medium    T1098.001 T1552            -                                    5.5
E02   unrotated-secret                 emerging      medium    T1555.006                  -                                    5.2
E03   secret-without-expiry            emerging      low       T1555.006                  -                                    5.2
E04   shared-credential                emerging      high      T1552 T1555.006            -                                    5.2
E05   unowned-workload-identity        emerging      medium    T1078.004 T1098.001        -                                    5.5 6.2
E06   unsponsored-agent                emerging      medium    T1078.004                  LLM06                                5.5 6.2
E07   overprivileged-agent             emerging      high      T1078.004 T1098.003        AML.T0053 LLM06                      6.8
E08   agent-reads-secrets              emerging      high      T1555.006                  AML.T0053 LLM02 LLM06                6.8
E09   agent-tool-beyond-purpose        emerging      medium    -                          AML.T0053 LLM06                      6.8
E10   agent-key-connection             emerging      medium    T1552 T1528                -                                    5.2
E11   shared-agent-identity            emerging      medium    T1078.004                  LLM06                                5.5
E12   broad-federated-subject          emerging      high      T1484.002 T1199 T1078.004  -                                    6.8
E13   agent-untrusted-input-path       emerging      critical  T1078.004                  AML.T0051.001 AML.T0053 LLM01 LLM06  6.8
```
<!-- /output -->

## Detail

<!-- output: rules --detail -->
```text
P01  standing-privileged-role  [high, privilege]
  Standing directory admin role outside PIM
  why: A person holds a powerful Entra ID role permanently instead of activating it when needed, so
       a stolen session or token is an admin session at any hour.
  fix: Make the assignment eligible in Privileged Identity Management with MFA, justification and
       approval on activation, and remove the permanent assignment.
  maps to: ATT&CK T1078.004 T1098.003; CIS 5.4 6.8; Zero Trust: least privilege
  remediation action: convert-to-eligible

P02  standing-azure-admin  [high, privilege]
  Standing Owner-level Azure role on a subscription
  why: A person can change role assignments across a whole subscription at any time, which is the
       shortest route to taking over every workload in it.
  fix: Move the assignment to PIM for Azure resources (eligible, time-bound, approval) and keep a
       scoped Contributor or Reader role for daily work.
  maps to: ATT&CK T1078.004 T1098.003; CIS 5.4 6.8; Zero Trust: least privilege
  remediation action: convert-to-eligible

P03  workload-subscription-privilege  [high, privilege]
  Workload identity with write or control on a whole subscription
  why: An application or managed identity can change most resources in a subscription. Anyone who
       gets its credential, or code execution where it runs, inherits that reach.
  fix: Replace the subscription-wide role with the narrowest built-in or custom role at the resource
       or resource group the workload actually touches.
  maps to: ATT&CK T1078.004 T1552.005 T1651; CIS 5.5 6.8; Zero Trust: least privilege
  remediation action: narrow-workload-role

P04  high-risk-app-permission  [critical, privilege]
  Application permission that amounts to tenant control or broad write
  why: The app holds a Microsoft Graph application permission that lets it grant roles, add
       credentials to other apps or rewrite the directory without any user present.
  fix: Remove the permission and grant the least-privileged alternative listed in the evidence; if
       the workload truly needs it, isolate the app and monitor every use.
  maps to: ATT&CK T1098.003 T1550.001; CIS 6.8; Zero Trust: least privilege
  remediation action: remove-app-permission

P05  human-path-to-crown-jewel  [critical, privilege]
  Non-admin person with a standing path to a crown jewel
  why: The person holds no admin role, yet a chain of ownerships, group memberships, roles and run-
       as identities lets them reach Global Administrator, production subscription control, every
       production secret or the production agent project.
  fix: Break the weakest link in the path shown in the evidence (usually an app ownership, a broad
       group role or a privileged managed identity) and re-run the scan.
  maps to: ATT&CK T1078.004 T1098.001 T1651; CIS 6.8 5.4; Zero Trust: assume breach
  remediation action: break-path

P06  guest-with-privilege  [high, privilege]
  Guest account with write or admin access
  why: An account owned by another organisation can change resources here. Its sign-in security,
       lifecycle and offboarding are outside this tenant's control.
  fix: Remove the role or replace it with an eligible, time-bound assignment covered by an access
       review and a guest-specific Conditional Access policy.
  maps to: ATT&CK T1199 T1078.004; CIS 6.1 6.2; Zero Trust: verify explicitly
  remediation action: remove-role

P07  external-app-with-privilege  [high, privilege]
  External multi-tenant app with write or secret access
  why: An app published by another organisation can change resources or read secrets here, so a
       breach at the vendor becomes a breach here.
  fix: Reduce the app to the read-only scope its contract needs, prefer vendor access through a
       customer-managed identity, and review it with the vendor.
  maps to: ATT&CK T1199; CIS 15.1 6.8; Zero Trust: assume breach
  remediation action: remove-role

P08  risky-consent-grant  [high, privilege]
  Tenant-wide consent to an unverified app for mail, files or directory
  why: Every user's mailbox, files or directory data can be read or changed by an app whose
       publisher is not verified, through a consent that never expires on its own.
  fix: Revoke the grant, restrict user consent to verified publishers and low-risk scopes, and route
       requests through the admin consent workflow.
  maps to: ATT&CK T1528 T1550.001; CIS 2.5 6.1; Zero Trust: verify explicitly
  remediation action: revoke-consent

F01  no-mfa-registered  [high, foundational]
  Enabled member account with no MFA method registered
  why: The account can only prove who it is with a password, so password spraying or a reused
       password is enough to sign in.
  fix: Require MFA registration through Conditional Access (registration campaign or the security
       info registration policy) and follow up with the user.
  maps to: ATT&CK T1110.003 T1078.004; CIS 6.3 6.4; Zero Trust: verify explicitly
  remediation action: require-mfa-registration

F02  privileged-without-enforced-mfa  [critical, foundational]
  Privileged person outside every enforced MFA policy
  why: The person holds or can activate an admin role, but no enabled Conditional Access policy
       requires MFA from them, usually because of an exclusion group.
  fix: Remove the person from the exclusion and add a phishing-resistant MFA policy that targets
       every admin role, eligible ones included.
  maps to: ATT&CK T1110.003 T1078.004; CIS 6.5; Zero Trust: verify explicitly
  remediation action: remove-ca-exclusion

F03  dormant-account  [medium, foundational]
  Enabled account with no sign-in for a long time
  why: Nobody is using the account, so nobody would notice if someone else started to. Dormant
       accounts with roles are favourite footholds.
  fix: Disable the account after confirming with its manager, then delete it after the retention
       period; use access reviews to catch the next one.
  maps to: ATT&CK T1078.004; CIS 5.3; Zero Trust: assume breach
  remediation action: disable-account

F04  emergency-account-weak-method  [high, foundational]
  Break-glass account without a phishing-resistant method
  why: Emergency accounts sit outside Conditional Access by design, so the method on the account is
       their only protection. A password alone is not enough.
  fix: Register FIDO2 security keys stored in separate safes, alert on every sign-in, and test the
       accounts on a schedule.
  maps to: ATT&CK T1110 T1078.004; CIS 6.5; Zero Trust: verify explicitly
  remediation action: register-phishing-resistant-method

F05  legacy-auth-not-blocked  [high, foundational]
  Legacy authentication is not blocked
  why: Old protocols cannot do MFA, so while they are allowed, MFA policies can be bypassed with
       just a password.
  fix: Switch the legacy-authentication block policy from report-only to on after checking the sign-
       in logs for remaining legacy clients.
  maps to: ATT&CK T1110.003; CIS 6.3; Zero Trust: verify explicitly
  remediation action: enforce-ca-policy

F06  vault-legacy-access-policies  [medium, foundational]
  Key Vault on the legacy access-policy model
  why: Access policies cannot be scoped, made eligible or audited like Azure roles, and anyone with
       Contributor on the vault can add themselves to them.
  fix: Migrate the vault to Azure RBAC, map each policy to Key Vault Secrets User or Officer at the
       narrowest scope, and close public network access.
  maps to: ATT&CK T1555.006; CIS 6.8 3.3; Zero Trust: least privilege
  remediation action: migrate-vault-rbac

F07  saas-admin-outside-sso  [high, foundational]
  SaaS admin account outside the SSO lifecycle
  why: An administrator in a SaaS app either signs in with a local password that bypasses Entra ID,
       or belongs to an Entra account that is disabled, so offboarding never reached the SaaS app.
  fix: Remove or disable the SaaS admin account, keep only SSO-linked admins provisioned through
       SCIM, and keep one documented local break-glass account if the vendor requires it.
  maps to: ATT&CK T1078.003 T1078.004; CIS 5.4 6.7; Zero Trust: verify explicitly
  remediation action: remove-saas-admin

E01  long-lived-app-secret  [medium, emerging]
  Client secret valid for longer than policy
  why: A password credential that lives for years is likely copied into scripts and pipelines; once
       leaked it keeps working until someone notices.
  fix: Replace the secret with a federated credential or managed identity, or failing that a
       certificate, and enforce a maximum lifetime with an app management policy.
  maps to: ATT&CK T1098.001 T1552; CIS 5.5; Zero Trust: assume breach
  remediation action: replace-secret

E02  unrotated-secret  [medium, emerging]
  Key Vault secret not rotated within the rotation window
  why: The secret value has not changed for over a year, so every copy ever made of it still works.
  fix: Rotate the secret, automate rotation with an Event Grid near-expiry trigger, and prefer an
       Entra ID connection that needs no secret.
  maps to: ATT&CK T1555.006; CIS 5.2; Zero Trust: assume breach
  remediation action: rotate-secret

E03  secret-without-expiry  [low, emerging]
  Key Vault secret without an expiry date
  why: Nothing will force a rotation or warn before the secret goes stale.
  fix: Set an expiry date and a near-expiry alert; enforce it with the Azure Policy definition for
       secret expiration.
  maps to: ATT&CK T1555.006; CIS 5.2; Zero Trust: assume breach
  remediation action: set-expiry

E04  shared-credential  [high, emerging]
  One secret used by several consumers
  why: Several connections or workloads use the same secret, so its activity cannot be attributed,
       it cannot be rotated without coordinated breakage, and one leak exposes all of them.
  fix: Issue a separate credential per consumer, or better, move each consumer to its own Entra ID
       identity.
  maps to: ATT&CK T1552 T1555.006; CIS 5.2; Zero Trust: assume breach
  remediation action: split-credential

E05  unowned-workload-identity  [medium, emerging]
  Application with no active owner
  why: No enabled person is accountable for the app, so nobody reviews its permissions, rotates its
       credentials or notices misuse.
  fix: Assign at least two owners from the team that runs the workload, or disable the app if nobody
       claims it.
  maps to: ATT&CK T1078.004 T1098.001; CIS 5.5 6.2; Zero Trust: assume breach
  remediation action: assign-owner

E06  unsponsored-agent  [medium, emerging]
  AI agent whose identity has no active sponsor
  why: The agent identity has no sponsor (or only disabled ones), so nobody answers for what the
       agent does or decides when it should be retired.
  fix: Assign an active sponsor from the owning team on the agent identity; retire the agent if
       nobody will sponsor it.
  maps to: ATT&CK T1078.004; OWASP LLM LLM06; CIS 5.5 6.2; Zero Trust: assume breach
  remediation action: assign-sponsor

E07  overprivileged-agent  [high, emerging]
  AI agent identity with write or admin rights
  why: The identity the agent runs as can change Azure resources or the directory. Anything that
       steers the agent (a prompt injection, a poisoned tool result) can use that power.
  fix: Give the agent a read-only or task-specific role at the narrowest scope, and put any write
       behind a separate tool that needs human approval.
  maps to: ATT&CK T1078.004 T1098.003; ATLAS AML.T0053; OWASP LLM LLM06; CIS 6.8; Zero Trust: least privilege
  remediation action: remove-agent-role

E08  agent-reads-secrets  [high, emerging]
  AI agent identity can read Key Vault secrets
  why: The agent can read secret values directly, so a manipulated agent can disclose credentials in
       its output or use them elsewhere.
  fix: Remove the secret-read role; give tools Entra ID connections or project-managed connections
       so the model path never sees a secret.
  maps to: ATT&CK T1555.006; ATLAS AML.T0053; OWASP LLM LLM02 LLM06; CIS 6.8; Zero Trust: least privilege
  remediation action: remove-agent-role

E09  agent-tool-beyond-purpose  [medium, emerging]
  AI agent with a tool its purpose does not need
  why: The agent can call a tool whose capability is outside the profile for its declared purpose,
       which widens what a hijacked agent can do.
  fix: Remove the tool, or move the capability to a separate agent with its own identity and an
       approval step.
  maps to: ATLAS AML.T0053; OWASP LLM LLM06; CIS 6.8; Zero Trust: least privilege
  remediation action: remove-tool

E10  agent-key-connection  [medium, emerging]
  Agent connection that authenticates with an API key
  why: The connection carries a static key instead of an Entra ID token, so the key can leak, is
       shared by everything using the connection, and cannot be scoped per agent.
  fix: Switch the connection to Microsoft Entra ID (managed identity or agent identity)
       authentication where the target supports it; otherwise rotate the key and scope it per
       consumer.
  maps to: ATT&CK T1552 T1528; CIS 5.2; Zero Trust: verify explicitly
  remediation action: switch-connection-auth

E11  shared-agent-identity  [medium, emerging]
  Several agents run as one identity
  why: Agents sharing an identity get the union of each other's access, and logs cannot tell which
       agent did what.
  fix: Create one agent identity per agent from the blueprint and give each only the roles its own
       purpose needs.
  maps to: ATT&CK T1078.004; OWASP LLM LLM06; CIS 5.5; Zero Trust: least privilege
  remediation action: split-identity

E12  broad-federated-subject  [high, emerging]
  Federated credential that trusts too many workflows
  why: The credential accepts tokens from pull requests, from any branch or from every repository in
       the organisation, so code that never went through review can sign in as this identity.
  fix: Restrict the subject to a protected environment (repo:org/repo:environment:prod) or one
       protected branch, and require reviewers on that environment.
  maps to: ATT&CK T1484.002 T1199 T1078.004; CIS 6.8; Zero Trust: verify explicitly
  remediation action: restrict-federated-subject

E13  agent-untrusted-input-path  [critical, emerging]
  Agent reads untrusted content and can reach a crown jewel
  why: The agent processes content from outside (documents, email, chat, web) and its identity or
       tools lead to a crown jewel, so one successful indirect prompt injection is a route to the
       most sensitive assets.
  fix: Cut the path (remove the privileged role or tool), keep untrusted-content agents read-only,
       and add input screening plus human approval for any high-impact action.
  maps to: ATT&CK T1078.004; ATLAS AML.T0051.001 AML.T0053; OWASP LLM LLM01 LLM06; CIS 6.8; Zero Trust: assume breach
  remediation action: break-path
```
<!-- /output -->
