# Enterprise / Commercial Edition

This project is offered under two editions:

## 1. Community Edition (FOSS)

The Community Edition is released under the GNU Affero General Public License v3 (AGPLv3).

Intended for:
- individual users and researchers
- evaluation / prototyping
- internal lab / security testing

You are allowed to:
- read and study the source code
- modify it
- run it internally

Obligations under AGPLv3:
- If you distribute modified firmware/binaries/libraries to third parties, you must provide the corresponding source code of your modifications.
- If you run a modified version of this project as a network-accessible service (internal or external), you must offer the source code of those modifications to the users of that service.
- No warranty, no support, no SLA.
- Enterprise features (bulk provisioning, multi-user policy enforcement, device inventory / revocation, corporate PIN rules, custom attestation/identity, etc.) are NOT included.

The Community Edition will continue to exist.

## 2. Enterprise / Commercial Edition

The Enterprise / Commercial Edition is a proprietary license for organizations that need to:

- deploy this in production at scale (multiple devices / multiple users / multiple teams)
- integrate it into their own physical product or appliance
- run it as an internal service (VM / container / private cloud "HSM / auth backend") for multiple internal teams or tenants
- enforce internal security policy (admin vs user roles, mandatory PIN rules, secure offboarding / revocation)
- avoid any AGPLv3 disclosure obligations for their own modifications and integration code

### What the Enterprise Edition provides

**Base license package (always included):**
- **Commercial license (proprietary).**
  You may run and integrate the software/firmware in production — including virtualized / internal-cloud style deployments — without being required to disclose derivative source code under AGPLv3.
- **Official signed builds.**
  You receive signed builds from the original developer so you can prove integrity and provenance.
- **Onboarding call (up to 1 hour).**
  A live remote session to get you from "we have it" to "it’s actually running in our environment" with minimal guesswork.

**Optional enterprise components (available on demand, scoped and priced per customer):**
- **Production / multi-user readiness.**
  Permission to operate the system with multiple users, multiple devices and multiple teams in real environments.
- **Bulk / fleet provisioning.**
  Automated enrollment for many tokens/devices/users at once (CSV / directory import), scripted onboarding of new users, initial PIN assignment / reset workflows, and role-based access (admin vs user).
- **Policy & lifecycle tooling.**
  Corporate PIN policy enforcement, per-user / per-team access control, device inventory / traceability, and secure revocation / retirement when someone leaves.
- **Custom attestation / per-organization identity.**
  Per-company certificate chains and attestation keys so devices can prove "this token/HSM is officially ours," including anti-cloning / unique device identity for OEM and fleet use.
- **Virtualization / internal cloud deployment support.**
  Guidance and components to run this as an internal service (VM, container, private-cloud HSM/auth backend) serving multiple internal teams or tenants under your brand.
- **Post-quantum (PQC) key material handling.**
  Integration/roadmap support for PQC algorithms (auth / signing) and secure PQC key storage inside the device or service.
- **Hierarchical deterministic key derivation (HD).**
  Wallet-style hierarchical key trees (BIP32-like concepts adapted to this platform) for issuing per-user / per-tenant / per-purpose subkeys without exporting the root secret — e.g. embedded wallet logic, tenant isolation, firmware signing trees, large fleets.
- **Cryptographically signed audit trail / tamper-evident event logging.**
  High-assurance logging of sensitive actions (key use, provisioning, PIN resets, revocations) with integrity protection for forensic / compliance needs.
- **Dual-control / two-person approval ("four-eyes").**
  Require multi-party authorization for high-risk actions such as firmware signing, key export, or critical configuration changes — standard in high-assurance / regulated environments.
- **Secure key escrow / disaster recovery design.**
  Split-secret or escrowed backup strategies so you don’t lose critical signing keys if a single admin disappears or hardware is lost.
- **Release-signing / supply-chain hardening pipeline.**
  Reference tooling and process so every production firmware/binary is signed with hardware-backed keys, proving origin and preventing tampering in transit or at manufacturing.
- **Policy-locked hardened mode ("FIPS-style profile").**
  Restricted algorithms, debug disabled, no raw key export, tamper-evident configuration for regulated / high-assurance deployments.
- **Priority support / security response SLA.**
  A direct line and guaranteed response window for production-impacting security issues.
- **White-label demo / pre-sales bundle.**
  Branded demo firmware + safe onboarding script so you can show "your product" to your own customers without exposing real production secrets.

These components are NOT automatically bundled. They are available case-by-case depending on your use case and are priced separately.

### Licensing models

- **Internal Use License**
  Internal production use within one legal entity (your company), including internal private cloud / virtualized deployments for multiple internal teams.
  Optional enterprise components can be added as needed.

- **OEM / Redistribution / Service License**
  Integration into a product/appliance you ship to customers, OR operating this as a managed service / hosted feature for external clients or third parties.
  Optional enterprise components (attestation branding, PQC support, HD key derivation, multi-tenant service hardening, audit trail, etc.) can be added as required.

Pricing depends on scope, fleet size, number of users/tenants, regulatory requirements, and which optional components you select.

### Request a quote

Email: pol@henarejos.me
Subject: `ENTERPRISE LICENSE <your company name>`

Please include:
- Company name and country
- Intended use:
  - Internal private deployment
  - OEM / external service to third parties
- Approximate scale (number of devices/tokens, number of users/tenants)
- Which optional components you are interested in (bulk provisioning, policy & lifecycle tooling, attestation branding / anti-cloning, virtualization/cloud, PQC, HD key derivation, audit trail, dual-control, key escrow, supply-chain signing, hardened mode, SLA, white-label demo)

You will receive:
1. A short commercial license agreement naming your company.
2. Access to the base package (and any optional components agreed).
3. Scheduling of the onboarding call.

## Why Enterprise exists

- Companies often need hardware-backed security (HSM, FIDO2, OpenPGP, etc.) under their own control, but cannot or will not open-source their internal security workflows.
- They also need multi-user / fleet-management features that hobby users do not.
- The commercial license funds continued development, maintenance and new hardware support.

The Community Edition remains AGPLv3.
The Enterprise Edition is for production, scale, and legal clarity.
