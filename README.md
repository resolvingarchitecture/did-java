# RA Decentralized IDentification (DID) Service - Java
Implementing [Web Of Trust](https://en.wikipedia.org/wiki/Web_of_trust) with Self Sovereign Identity.

[W3C DID](https://w3c.github.io/did-core/) interoperability is kept as a guideline. RA will
**not** register its own DID method — see [`../DESIGN.md`](../DESIGN.md) §5, which produces a
`did:nostr` view of the key instead.

Uses Key Ring Service to Manage the Physical Persistence, Generation, Encryption, Decryption, Revocation, and Destruction of Keys

## Status

The current Java implementation runs as the identity and key-management layer for
[1M5](https://1m5.io) — node and account identities, key management, signing, and verification for
an infrastructure-independent communications system. That is where the design gets its requirements
and its testing.

## Direction — off OpenPGP

The working implementation is built on **OpenPGP key rings**: RSA keys, GnuPG-style keyring
files persisted locally, and PGP key signatures for the web of trust. It works, but the
OpenPGP ecosystem carries a lot of weight — large keys, awkward key distribution, and a trust
model that few people ever really operated. In practice that weight is most of what makes
self-sovereign identity feel impractical to build on.

The replacement is specified one level up, for the whole DID effort rather than this
implementation alone:

- **[`../STRATEGY.md`](../STRATEGY.md)** — why identity adoption keeps failing and the plan
  for doing better: ride Nostr rather than bootstrap a network, own the gap it still has (key
  recovery and attestation), and ship a specification and a small library before a product.
- **[`../DESIGN.md`](../DESIGN.md)** — the technical specification: `secp256k1` / BIP-340
  Schnorr identities, Nostr-compatible signed records, attestations as a decentralized
  replacement for NIP-05, guardian-based recovery and rotation, and a `did:nostr`
  compatibility view.

Two reversals from what this README previously said: there will be **no RA-specific DID
method** (a `did:nostr` community draft already exists — contribute to that instead), and
**relays are an opt-in distribution option, not the architecture** — signed records are
transport-agnostic.

Everything below describes the OpenPGP implementation that exists today. `../DESIGN.md` §7.3
lists what changes in this module: a `NostrKeyRing` alongside `OpenPGPKeyRing`, a successor to
the PGP-typed `KeyRing` interface, a real `vouch`, and several defect fixes.

## Abstract (from W3C)
Decentralized identifiers (DIDs) are a new type of identifier to provide verifiable, decentralized digital identity.
These new identifiers are designed to enable the controller of a DID to prove control over it and to be implemented
independently of any centralized registry, identity provider, or certificate authority. DIDs are URLs that relate a
DID subject to a DID document allowing trustable interactions with that subject. DID documents are simple documents
describing how to use that specific DID. Each DID document can express cryptographic material, verification methods,
or service endpoints, which provide a set of mechanisms enabling a DID controller to prove control of the DID.
Service endpoints enable trusted interactions with the DID subject.

## Bill of Rights

From https://github.com/WebOfTrustInfo/self-sovereign-identity/blob/master/self-sovereign-identity-bill-of-rights.md
and how we plan on supporting them.

### Individuals must be able to establish their existence as a unified identity online and in the physical world
A unified identity requires that people not only have an online presence, but that presence must function seamlessly
across both online and real-world environments. One unified identity for all spheres of life.

One unified identity can come about through individual projects by supporting common standards.
1M5 will only use standard algorithms well supported globally and any standard interfaces that become widely adopted
so long as those interfaces come from open source and free efforts.

* AES symmetric keys for encrypting identity keys and as session keys
* SHA256 hashing for signatures and other integrity verifications
* ElGamal for asymmetric keys
* Multiple identities per person are supported to take into consideration different aspects of life

### Individuals must have the tools to access and control their identities
Self-sovereign identity holders must be able to easily retrieve identity attributes and verified claims as well
as any metadata that has been generated in the process of transactions. There can be no personally identifiable
information (PII) data that is hidden from the identity holder. This includes management, updating or changing
identity attributes, and keeping private what they choose.

* Service interfaces for managing identities that can be called by user interface based applications.
* Identity Keys lost can be recovered through verification with an established reputation via friends and family.

### The platforms and protocols on which self-sovereign identities are built, must be open and transparent
This refers to how the platforms and protocols are governed, including how they are managed and updated.
They should be open-source, well-known, and as independent as possible of any particular architecture;
anyone should be able to examine how they work.

* All code in this project is open source, released under the MIT license.

### Users must have the right to participate in the governance of their identity infrastructure
The platform, protocols on which self-sovereign identities are built, must be governed by identity holders.
By definition, if the platform is governed by a private entity or limited set of participants, the Identity holder
is not in control of the future of their identity.

1M5 will be governed by members and membership will be open to those using it through their public keys (identities).
Governance within the application will be supported in the future by members, especially with the implementation of [V4D](http://v4d.gaiagloaming.io).

### Identities must exist for the life of the identity holder

While the platform and protocols evolve, each singular identity must remain intact. This must not contradict a
"right to be forgotten"; a user should be able to dispose of an identity if he or she wishes and claims should
be modified or removed as appropriate over time. To do this requires a firm separation between an identity and
its claims: they can't be tied forever.

* 1M5 is a decentralized autonomous organization in that it is not registered in any jurisdiction and thus will exist so long as there is membership.
* All keys and the data they have access to can be deleted from the system at any time.
* Data provided to another party is a one-time copy provided to the other party and no longer revocable unless maintained with the other party in 1M5.
* Any recurring data access to another party can be immediately canceled at any time.

### Identities must be portable

Identity attributes and verified claims must be controlled personally and be transportable and interoperable
as desired. Government entities, companies and other individuals can come and go. So it is essential that
identity holders can move their identity data to other platforms to ensure that they alone
control their identity.

* Using common standards today and as the industry evolves while ensuring keys can be imported, exported, and mapped to new technologies as they evolve.

### Identities must be interoperable

Identity holders must be able to use their identities in all facets of their lives. So any identity platform
or protocol must function across geographical, political and commercial jurisdictions. Identities should be as
widely usable as possible. Ultimately, identities are of little value if they only work in niches.

* Common interfaces will be supported so long as they do not violate free and open source systems.

### Individuals must consent to the use of their identity

The point of having an identity is that you can use it to participate in mutually beneficial
transactions — whether personal or commercial. This requires that some amount of personal information
needs to be shared. However, any sharing of personal data must require the absolute consent of the
user — even if third parties have a record of previously verified claims. For every transaction associate
with a claim, the identity holder must deliberately consent to its use.

* Only public keys can be given out.
* If a 'power of attorney' type action is desired (such as for the elderly), it can be set up to support that without giving away private keys. (Expected in future development).

### Disclosure of verified claims must be minimized

For every transaction, only the minimum amount of personally identifiable information should be required
and shared. If an identity holder wants to enable an age-related commercial transaction, e.g. buy alcohol,
the only verified claim that needs to be share is whether they are over 21. There is not need to share actual age,
street address, height, weight, etc.

* Access can be given to data at the lowest attribute level explicitly approved by the member.
* Data can be shown to 3rd parties if the member wishes as in the example with being old enough to purchase alcohol in a jurisdiction requiring proof of age but all data owned by the user is managed by the user to uphold voluntaryism.
* The only rules to be followed within 1M5 is ethics and it's defined to be the non-aggression principle / voluntary relationships (voluntaryism).

### The rights of identity holders must supersede any other platform or ecosystem entities

If a conflict arises between the needs of the platform or entities engaging with identity holders, the
governance must be designed to err on the side of preserving these rights for identity holder over the
needs of the protocols, platform or network. To ensure this, identity authentication must be decentralized,
independent, and free of censorship.

* Decentralized: 1M5 only uses P2P open source free software systems
* Independent: 1M5 is a DAO with no jurisdiction oversight, only member oversight
* Free of Censorship: anonymous highly censorship resistant communications with strong at-rest data encryption

## Design Goals
We share design goals from the [W3C spec](https://w3c-ccg.github.io/did-spec/#design-goals):

| Goal | Description |
|------|-------------|
| Decentralization | DID architecture should eliminate the requirement for centralized authorities or single points of failure in identifier management, including the registration of globally unique identifiers, public verification keys, service endpoints, and other metadata. |
| Self‑Sovereignty | DID architecture should give entities, both human and non-human, the power to directly own and control their digital identifiers without the need to rely on external authorities. |
| Privacy | DID architecture should enable entities to control the privacy of their information, including minimal, selective, and progressive disclosure of attributes or other data. |
| Security | DID architecture should enable sufficient security for relying parties to depend on DID Documents for their required level of assurance. |
| Proof-based | DID architecture should enable the DID subject to provide cryptographic proof of authentication and proof of authorization rights. |
| Discoverability | DID architecture should make it possible for entities to discover DIDs for other entities to learn more about or interact with those entities. |
| Interoperability | DID architecture should use interoperable standards so DID infrastructure can make use of existing tools and software libraries designed for interoperability. |
| Portability | DID architecture should be system and network-independent and enable entities to use their digital identifiers with any system that supports DIDs and DID Methods. |
| Simplicity | To meet these design goals, DID architecture should be (to paraphrase Albert Einstein) "as simple as possible but no simpler". |
| Extensibility | When possible, DID architecture should enable extensibility provided it does not greatly hinder interoperability, portability, or simplicity. |

## Features and Roadmap
The DID Service is being implemented as individual projects needs arise.

SHA-1 is used throughout while still in testing mode. Will move to SHA-256
prior to production release.

### TBD
- Moving key handling off OpenPGP key rings onto `secp256k1` / BIP-340 Schnorr keys and signed
  attestations — specified in [`../DESIGN.md`](../DESIGN.md); §7.3 lists the changes landing
  in this module.
- Adding Reputation support for signers signing attributes of signees. Note `../DESIGN.md`
  §3.5 treats trust scoring as a client concern, so this may become an attestation query
  rather than a `Reputation` class.

### 1.2
- Converging with KeyRingService.
- Beginning of YubiKey integration.

### 1.1
- Symmetric Encryption/Decryption

### 1.0
- OpenPGP Key Rings Collections Generation, Key Rings Creation/Deletion, Encryption, Decryption, Signing, Verify Signatures.
- Keys persisted locally.


## License

MIT — see [`LICENSE`](LICENSE).
