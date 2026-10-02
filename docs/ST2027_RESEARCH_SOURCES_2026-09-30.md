# ST2027 research source register

Research cut-off: **30 September 2026**. Companion: [implementation plan](ST2027_IMPLEMENTATION_PLAN.md).

## Scope and evidence discipline

This is a focused engineering literature review, not an exhaustive systematic review or a cryptographic certification. General web-search queries returned no results in this session. Discovery therefore used live NIST/IETF sites, the USENIX Security 2026 programme, IACR ePrint search, and references from retrieved papers. NSA web pages and a media.defense.gov document returned HTTP 403. Current NSA programme requirements, approved product lists, procurement dates, and country-specific authorizations remain **deployment verification gates**.

The register distinguishes full specifications, selected full-paper sections, publisher abstracts, project documentation, and preprints. An abstract is not a reviewed proof. Newness does not make a proposal safe to deploy. Dates are publication/revision dates shown by the retrieved sources, not inferred from a site's copyright footer. All sources below were accessed on 2026-09-30.

The plan synthesizes research spanning 1975–2026; it does not represent an author possessing 50 years of operational experience. Recommendations and proposed test thresholds belong to this project unless explicitly attributed to a source.

## Foundational principles and cryptographic standards

### R01 — Saltzer and Schroeder: The Protection of Information in Computer Systems (1975)
- Source: https://web.mit.edu/Saltzer/www/publications/protection/
- Reviewed: https://web.mit.edu/Saltzer/www/publications/protection/Basic.html — full HTML section I, particularly design principles.
- Status: foundational published systems-security paper.
- Lesson: economy of mechanism, fail-safe defaults, complete mediation, open design, separation of privilege, least privilege, least common mechanism, and usable protection are architecture requirements, not slogans. More security features can increase the attack surface.

### R02 — NIST FIPS 203: ML-KEM (13 August 2024)
- Source: https://csrc.nist.gov/pubs/fips/203/final
- Reviewed: official publication page and its 17 November 2025 errata notice; not the errata spreadsheet itself.
- Status: final standard, with potential corrections to track.
- Lesson: ML-KEM-1024 is a standardized parameter set. Standardization is not a promise of a calendar lifetime and does not validate this project's implementation. Freeze the precise standard/errata baseline during provider qualification.

### R03 — NIST FIPS 204: ML-DSA (13 August 2024)
- Source: https://csrc.nist.gov/pubs/fips/204/final
- Reviewed: official publication page, including the 31 July 2026 potential-update notice; spreadsheet contents not reviewed.
- Status: final standard.
- Lesson: use the correct signature variant and context handling, not just an algorithm name. Include errata review and test-vector provenance in release qualification.

### R04 — NIST Post-Quantum Cryptography programme (updated 5 August 2026)
- Source: https://csrc.nist.gov/projects/post-quantum-cryptography
- Reviewed: current programme overview.
- Status: official programme information.
- Lesson: ML-KEM, ML-DSA, and SLH-DSA are standardized; the retrieved page describes Falcon and HQC standardization as ongoing. Do not label Classic McEliece a FIPS 203 algorithm, or every NIST PQ signature a CNSA communications-suite member. Selection, standardization, implementation validation, and deployment authorization are separate.

### R05 — NIST SP 800-227: Recommendations for KEMs (18 September 2025)
- Sources: https://csrc.nist.gov/pubs/sp/800/227/final ; https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-227.pdf
- Reviewed: publication page and downloaded full-text excerpts, §§3.3, 4.1–4.3, 4.6.3 (printed pp.14–19, 31–32).
- Status: final guidance.
- Lesson: KEM security requires device security, authenticated channels, correct key usage, and implementation protections. A generic KDF of two shared secrets is not automatically an IND-CCA-preserving combiner. Composite schemes add complexity and downgrade risks. Use a specified construction with its actual binding assumptions.

### R06 — RFC 10024: PQ/T Hybrid Key Agreement Mechanisms for TLS 1.3 (August 2026)
- Sources: https://www.rfc-editor.org/info/rfc10024 ; https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/
- Reviewed: full RFC text and publication status, including §§4–6.
- Status: Proposed Standard; the draft URL redirects to the RFC.
- Lesson: SecP384r1MLKEM1024 is a specified TLS hybrid. Section 6 explicitly ties the analysis to the TLS transcript; it does **not** certify the repository's custom Noise-like construction or arbitrary X25519+ML-KEM-1024 transport. The P-384 hybrid share is 1,665 bytes and needs bounded fragmentation on small datagrams.

### R07 — CNSA Suite 2.0 Profile for TLS 1.3, draft-becker-cnsa2-tls-profile-05 (19 July 2026)
- Sources: https://www.ietf.org/archive/id/draft-becker-cnsa2-tls-profile-05.txt ; https://datatracker.ietf.org/api/v1/doc/document/draft-becker-cnsa2-tls-profile/
- Reviewed: full draft; current revision/status checked through Datatracker.
- Status: **Informational Internet-Draft**, not an IETF standard; expires 20 January 2027. Normative language is confined to its proposed profile.
- Lesson: specifies pure ML-KEM-1024, ML-DSA-87, TLS_AES_256_GCM_SHA384, certificate authentication, and no early data. HashML-DSA is not permitted in this draft; external-μ support has specified conditions. Its DTLS section matters to a paced datagram design. A hybrid TLS connection must not be silently labelled compliant with this pure-PQ profile.

### R08 — Signal PQXDH specification, revision 3 (updated 23 January 2024)
- Source: https://signal.org/docs/specifications/pqxdh/
- Reviewed: full specification and security considerations.
- Status: deployed-protocol specification, not a military approval.
- Lesson: asynchronous prekeys, identity binding, replay handling, and one-time-key deletion are essential. This revision explicitly distinguishes post-quantum confidentiality from classical-only mutual authentication. Copying PQXDH alone does not supply the required active-quantum authentication.

## Messaging, compromise recovery, and metadata research

### R09 — Bhargavan, Jacomme, Kiefer, Schmidt: Formal verification of PQXDH (USENIX Security 2024)
- Sources: https://www.usenix.org/conference/usenixsecurity24/presentation/bhargavan ; https://www.usenix.org/system/files/usenixsecurity24-bhargavan.pdf
- Reviewed: publisher page and full-paper introduction/contributions excerpts (printed pp.469–470).
- Status: peer-reviewed paper; ProVerif/CryptoVerif analysis.
- Lesson: public-key confusion, encoding ambiguities, and KEM re-encapsulation show why individually strong algorithms are insufficient. The reported specification weaknesses were not exploitable in Signal's examined implementation. Model typed encodings and identity/context binding explicitly.

### R10 — Dodis et al.: Triple Ratchet: A Bandwidth Efficient Hybrid-Secure Signal Protocol (EUROCRYPT 2025)
- Source: https://eprint.iacr.org/2025/078
- Reviewed: abstract, publication metadata, revision history (13 March 2025); not the complete proof.
- Status: ePrint describes a major revision of a EUROCRYPT 2025 publication.
- Lesson: erasure-coded ratchet messages smooth PQ overhead. Katana is a research construction; its proposed efficiency does not justify adding a new primitive to the deployment baseline. The proof does not automatically transfer to changed algorithms or scheduling.

### R11 — Auerbach et al.: How to Compare Bandwidth Constrained Two-Party Secure Messaging Protocols (USENIX Security 2025)
- Sources: https://www.usenix.org/conference/usenixsecurity25/presentation/auerbach ; https://www.usenix.org/system/files/usenixsecurity25-auerbach.pdf
- Reviewed: full conference paper, especially §§1.1, 3.2–3.3, 5 and Appendix A; no independent reproduction of the experiments.
- Status: peer-reviewed; publisher lists available, functional, and reproduced artifact badges.
- Lesson: compare **vulnerable message sets**, not merely rekey counts. There is no universally optimal protocol across messaging patterns. Offline and asymmetric traffic delay recovery; pre-generating future secrets can enlarge exposure. Some experimental protocol variants use mocked primitive implementations. This is not a performance certificate for ST2027.

### R12 — Signal: Signal Protocol and Post-Quantum Ratchets (2 October 2025)
- Source: https://signal.org/blog/spqr/
- Reviewed: full engineering article, including its research and formal-verification references.
- Status: primary implementation account, not independent certification.
- Lesson: SPQR/Triple Ratchet combines continuous PQ contributions, erasure coding, state machines, and ongoing verification. Published use of ML-KEM-768 cannot be turned into an approved ML-KEM-1024 profile by changing a constant. Any adaptation requires new vectors, review, and analysis. Do not keep describing Signal as having only an initial PQ handshake.

### R13 — Linker, Sasse, Basin: A Formal Analysis of Apple's iMessage PQ3 Protocol (USENIX Security 2025)
- Source: https://eprint.iacr.org/2024/1395
- Reviewed: abstract and metadata; revised 22 May 2025.
- Status: peer-reviewed publication with ePrint version.
- Lesson: Tamarin can model unbounded ratcheting and fine-grained compromise claims. These claims refer to a specific protocol and identity infrastructure, not to an arbitrary look-alike implementation.

### R14 — Cremers, Medinger, Naska: Impossibility Results for PCS in Real-World Communication Systems
- Source: https://eprint.iacr.org/2024/1886
- Reviewed: abstract and revision history (4 July 2025).
- Status: **preprint** according to retrieved metadata; theorem assumptions not independently checked.
- Lesson: state-loss tolerance and session-management choices can undermine end-user PCS even when a ratchet is secure. Explicitly test resets, session resurrection, device cloning, and backup restoration. Do not promise healing while an attacker retains device control.

### R15 — Truong, Terzo, Paterson: Message Injection Attacks Against Signal (USENIX Security 2026)
- Sources: https://www.usenix.org/conference/usenixsecurity26/presentation/truong ; https://www.usenix.org/system/files/usenixsecurity26-truong.pdf
- Reviewed: publisher abstract and full-paper discussion excerpts (printed pp.4259–4260), plus disclosure/patch references in extracted text.
- Status: peer-reviewed; authors report coordinated fixes deployed by Signal.
- Lesson: identity resolution, cross-component context loss, and missing key checks can break application integrity despite sound primitives. Preserve one authenticated identity/context object through decoding, session lookup, authorization, and display. This is evidence for integration testing, not a claim that current Signal is unpatched or inferior to ST2027.

### R16 — RFC 9420: Messaging Layer Security (July 2023)
- Source: https://datatracker.ietf.org/api/v1/doc/document/rfc9420/
- Reviewed: official metadata/abstract and references from the PQ extension; not all 132 RFC pages.
- Status: Proposed Standard; metadata lists verified errata.
- Lesson: use maintained MLS implementations for future group work rather than a new home-grown group ratchet. Base MLS alone does not imply PQ confidentiality/authentication.

### R17 — ML-KEM and Hybrid Cipher Suites for MLS, draft-ietf-mls-pq-ciphersuites-06 (21 July 2026)
- Sources: https://www.ietf.org/archive/id/draft-ietf-mls-pq-ciphersuites-06.txt ; https://datatracker.ietf.org/api/v1/doc/document/draft-ietf-mls-pq-ciphersuites/
- Reviewed: full draft and status metadata.
- Status: **Internet-Draft**, not an RFC; expires 22 January 2027.
- Lesson: the draft distinguishes PQ confidentiality-only suites from suites with PQ signatures. Its proposed ML-KEM-1024/AES-256-GCM/SHA-384/ML-DSA-87 suite is a candidate, not an assigned final interoperable deployment profile. Never assign guessed final codepoints.

### R18 — Hale, Tian, Wang: Benchmarking of the Amortized Post Quantum Combiner for MLS
- Source: https://eprint.iacr.org/2026/034
- Reviewed: abstract and metadata; submitted 8 January 2026; publication listed as SSR 2025.
- Status: published research, abstract-level review here.
- Lesson: PQ authentication has material bandwidth/memory costs. Reproduce workload-specific results; the abstract's approximately 1:50 sweet spot is not a universal military policy and does not establish fastest healing.

### R19 — Piotrowska et al.: The Loopix Anonymity System (USENIX Security 2017)
- Source: https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/piotrowska
- Reviewed: publisher abstract/architecture summary.
- Status: peer-reviewed foundational anonymity research.
- Lesson: sender/receiver anonymity involves mixes, cover traffic, topology, adversary assumptions, and latency trade-offs. Direct point-to-point padding is not equivalent to a mix network. A sovereign mix-network profile would require its own evaluation and PQ treatment.

### R20 — Qu et al.: Tracegram (USENIX Security 2026)
- Source: https://www.usenix.org/conference/usenixsecurity26/presentation/qu
- Reviewed: publisher abstract.
- Status: peer-reviewed traffic-analysis research.
- Lesson: adversaries can combine multiple flows and long time windows. Include trace-level and cross-flow evaluations, not just single-packet entropy. The paper does not directly evaluate or break ST2027.

## Implementation, hardware, sanitization, and assurance

### R21 — Guo, Nabokov, Johansson: Unlocking the True Potential of Decryption Failure Oracles (USENIX Security 2026)
- Source: https://www.usenix.org/conference/usenixsecurity26/presentation/guo-qian
- Reviewed: publisher abstract.
- Status: peer-reviewed side-channel research.
- Lesson: imperfect leakage oracles can still matter. Require decapsulation/error-path timing evaluation on the chosen hardware. The cited ML-KEM-768 query counts depend on a particular oracle and are **not** a generic remote break of ML-KEM, ML-KEM-1024, or this repository.

### R22 — Valsaraj et al.: When Randomness Isn't Random: Practical Fault Attack on Post-Quantum Lattice Standards
- Source: https://eprint.iacr.org/2025/2009
- Reviewed: abstract and metadata; revised 22 March 2026.
- Status: **preprint** in retrieved record.
- Lesson: reported laser fault-injection results on an STM32H7 implementation motivate independent hardware fault evaluation and protected RNG/key-generation paths. Do not generalize these implementation-specific results into a mathematical break of ML-KEM/ML-DSA.

### R23 — seL4: What the Proofs Assume
- Source: https://sel4.systems/Verification/assumptions.html
- Reviewed: full project documentation page.
- Status: authoritative project scope statement.
- Lesson: hardware, boot, DMA, assembly, and side-channel assumptions remain. A verified kernel or an environment-variable gate does not verify ST2027, drivers, or the complete appliance. Choose an actually supported verified platform/configuration.

### R24 — NIST SP 800-88 Revision 2: Guidelines for Media Sanitization (26 September 2025)
- Sources: https://csrc.nist.gov/pubs/sp/800/88/r2/final ; https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-88r2.pdf
- Reviewed: official page and downloaded full-text §§3.1–3.2.2 (printed pp.8–13). The page also lists a 17 July 2026 FAQ; FAQ contents not reviewed.
- Status: final; supersedes Revision 1.
- Lesson: distinguish clear, purge, and destroy; media-dependent verification is essential. File overwrites do not reliably reach flash spare cells. Cryptographic erase has strict prerequisites and may be unsuitable for extremely long-lived sensitive information. The text notes DoD removed NISPOM overwrite specifications in 2006. Do not claim that unlinking a file proves physical purge.

### R25 — NIST SP 800-90C: RBG Constructions (25 September 2025)
- Source: https://csrc.nist.gov/pubs/sp/800/90/c/final
- Reviewed: publication page/abstract and relation to SP 800-90A/B.
- Status: final.
- Lesson: qualify an entropy/DRBG construction and failure handling. Shannon entropy of ciphertext is not validation of the random-bit generator that created its key.

### R26 — NIST Cryptographic Module Validation Program
- Source: https://csrc.nist.gov/projects/cryptographic-module-validation-program
- Reviewed: current official programme overview, updated 21 August 2026.
- Status: regulatory programme information.
- Lesson: validation applies to specific modules and operational environments. The page identifies 21 September 2026 as the FIPS 140-2 historical-list transition for new systems. Check a selected module's current certificate, caveats, algorithm scope, and status; never infer classified-system approval from FIPS alone.

### R27 — NIST SP 800-218: Secure Software Development Framework v1.1 (February 2022)
- Source: https://csrc.nist.gov/pubs/sp/800/218/final
- Reviewed: official publication overview.
- Status: final guidance.
- Lesson: security development, provenance, vulnerability response, and root-cause remediation are lifecycle obligations, not a one-time test battery.

### R28 — SLSA v1.2: Build requirements
- Sources: https://slsa.dev/spec/v1.2/ ; https://slsa.dev/spec/v1.2/build-requirements
- Reviewed: full requirements page, especially unforgeable provenance and isolation.
- Status: approved specification.
- Lesson: signed self-generated JSON and matching local hashes are not SLSA Build L3. The builder's trusted control plane must generate/verify provenance; tenant build steps must not access provenance-signing secrets. Reproducibility is useful but distinct from these guarantees.

### R29 — The Update Framework specification v1.0.36 (5 August 2026)
- Source: https://theupdateframework.github.io/specification/latest/
- Reviewed: rendered specification through formats/roles, threat model, key rotation principles, and client-workflow outline; not every implementation detail.
- Status: published framework specification.
- Lesson: offline root, delegated targets, version/freshness checks, and threshold trust limit update compromise. A PQ signature extension needs its own documented interoperable format/provider support; ordinary TUF interoperability must not be assumed after substituting algorithms.

### R30 — Open Quantum Safe security policy
- Source: https://openquantumsafe.org/liboqs/security.html
- Reviewed: full page; project overview at https://openquantumsafe.org/ checked for current context.
- Status: upstream project guidance; partial external audit is linked.
- Lesson: OQS explicitly describes research/prototyping limitations and best-effort response. Existing use of liboqs is not enough to select a classified deployment provider. Audit scope and supported exact versions must be checked.

### R31 — libcrux upstream verification/maturity documentation
- Source: https://github.com/cryspen/libcrux (redirected to https://github.com/celabshq/libcrux)
- Reviewed: current README, maturity caveat and per-crate verification explanation.
- Status: candidate implementation documentation, not a validation certificate.
- Lesson: libcrux combines HACL* code and hax-based Rust verification, but proof scope varies by crate/features; top-level wrappers may not be verified. The README warns that compiled executables are not proven side-channel-resistant and advises contacting maintainers before production use. Evaluate exact artifacts, not the brand.

### R32 — RFC 9334: Remote ATtestation procedureS Architecture (January 2023)
- Source: https://datatracker.ietf.org/api/v1/doc/document/rfc9334/
- Reviewed: official metadata/abstract; implementation details are plan requirements, not claims of a full RFC audit here.
- Status: Informational RFC.
- Lesson: distinguish evidence generation, verification/appraisal, and the relying party's decision. A PCR value printed by a local process is not by itself authenticated, fresh remote evidence or proof of runtime integrity.

## Retrieval limitations and follow-up

- **Blocked:** https://www.nsa.gov/Cybersecurity/Post-Quantum-Cybersecurity-Resources/ and https://www.nsa.gov/Resources/Commercial-Solutions-for-Classified-Program/ returned HTTP 403. No live CSfC eligibility, component listing, or operational approval was verified.
- **Blocked:** an attempted NSA algorithms advisory at media.defense.gov returned HTTP 403. R07 supplies public algorithm-profile evidence but cannot replace sponsor confirmation of binding policy.
- R07 cites the CNSA FAQ at https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF ; that FAQ was not retrieved in this review.
- PDF web-fetch rendering was unsupported. Five public PDFs were downloaded to temporary research storage, and the sections declared above were read via PDF/text extraction. No repository secrets or operational messages were supplied to any website.
- **Not performed:** independent theorem checking, reproduction of paper benchmarks, vulnerability exploitation, full-code audit, provider certification lookup for a purchased module, physical diode testing, or validation of a production host.
- Before profile freeze, recheck errata, current draft revisions, assigned registries, library advisories, national rules, and product approvals. Preserve source/version identifiers in the engineering evidence package. Any source changes trigger impact review, not automatic production dependency upgrades.
