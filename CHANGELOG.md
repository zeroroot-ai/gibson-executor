# Changelog

## [0.110.1](https://github.com/zeroroot-ai/gibson-executor/compare/v0.110.0...v0.110.1) (2026-09-07)


### Bug Fixes

* **security:** bump recon tool modules, raise linked-dep floors, scope workflow tokens ([#18](https://github.com/zeroroot-ai/gibson-executor/issues/18)) ([ba11e66](https://github.com/zeroroot-ai/gibson-executor/commit/ba11e66e6c9ce3a0b9cbb779d1162bad3c1cd445))

## [0.110.0](https://github.com/zeroroot-ai/gibson-executor/compare/v0.109.0...v0.110.0) (2026-09-06)


### Features

* **trivy:** allow a mirrored vulnerability database repository ([#15](https://github.com/zeroroot-ai/gibson-executor/issues/15)) ([3a29b93](https://github.com/zeroroot-ai/gibson-executor/commit/3a29b93c1b2806053501eaf3b32074642b05315b))

## [0.109.0](https://github.com/zeroroot-ai/gibson-executor/compare/v0.108.0...v0.109.0) (2026-08-30)


### Features

* **httpx:** report missing and wrong security response headers ([#405](https://github.com/zeroroot-ai/gibson-executor/issues/405)) ([8f97f54](https://github.com/zeroroot-ai/gibson-executor/commit/8f97f541fbe09f7ac20d993e47879cd075b46be1)), closes [#400](https://github.com/zeroroot-ai/gibson-executor/issues/400)

## [0.108.0](https://github.com/zeroroot-ai/gibson-executor/compare/v0.107.5...v0.108.0) (2026-08-30)


### Features

* **ci:** prove every catalogued tool runs and parses inside the built image ([#401](https://github.com/zeroroot-ai/gibson-executor/issues/401)) ([2e7225e](https://github.com/zeroroot-ai/gibson-executor/commit/2e7225e79ad6dc7d44b47d68177538b6e14289d9))
* **tools:** tlsx probe emitting a Finding per weak protocol, cipher or certificate problem ([#404](https://github.com/zeroroot-ai/gibson-executor/issues/404)) ([3cde166](https://github.com/zeroroot-ai/gibson-executor/commit/3cde16601c351d8bfd8201dfe2414b0469dce177))
* **tools:** trivy image scan emitting Image, Package, Vulnerability and Findings ([#403](https://github.com/zeroroot-ai/gibson-executor/issues/403)) ([4857c80](https://github.com/zeroroot-ai/gibson-executor/commit/4857c8054663a46d88790578ce9b2d6d4553766c))

## [0.107.5](https://github.com/zeroroot-ai/gibson-executor/compare/v0.107.4...v0.107.5) (2026-08-16)


### Bug Fixes

* **image:** give the recon tools a dependency floor they cannot ignore ([#380](https://github.com/zeroroot-ai/gibson-executor/issues/380)) ([8b95ded](https://github.com/zeroroot-ai/gibson-executor/commit/8b95ded0f22ca48298121e8a26d5393fc62eb6e1))

## [0.107.4](https://github.com/zeroroot-ai/gibson-executor/compare/v0.107.3...v0.107.4) (2026-08-16)


### Bug Fixes

* **ci:** run release-please as the zeroday-sdk-fanout App ([#378](https://github.com/zeroroot-ai/gibson-executor/issues/378)) ([af18437](https://github.com/zeroroot-ai/gibson-executor/commit/af18437732082b37f62bad5aee3601b5dd9214c6))

## [0.107.3](https://github.com/zeroroot-ai/gibson-executor/compare/v0.107.2...v0.107.3) (2026-08-16)


### Bug Fixes

* **ci:** make golangci-lint actually block a merge ([#369](https://github.com/zeroroot-ai/gibson-executor/issues/369)) ([#373](https://github.com/zeroroot-ai/gibson-executor/issues/373)) ([03e5af3](https://github.com/zeroroot-ai/gibson-executor/commit/03e5af34e04f392050a65b51c860791b3e2222bf))
* **image:** remove amass from the catalog, no shippable version works ([#371](https://github.com/zeroroot-ai/gibson-executor/issues/371)) ([4b62a3e](https://github.com/zeroroot-ai/gibson-executor/commit/4b62a3eff7289133f0d2881a457d1deabd1c2551))

## [0.107.2](https://github.com/zeroroot-ai/gibson-executor/compare/v0.107.1...v0.107.2) (2026-08-15)


### Bug Fixes

* **amass:** deny -w and constrain -include/-exclude/-timeout args ([#135](https://github.com/zeroroot-ai/gibson-executor/issues/135)) ([330e0b9](https://github.com/zeroroot-ai/gibson-executor/commit/330e0b9dcf4ca47bc41ca850f785dd44d6e86d99))
* **ci:** bump reusable-image-build.yml pin to pick up main-branch Trivy scanning ([#348](https://github.com/zeroroot-ai/gibson-executor/issues/348)) ([2bc36f2](https://github.com/zeroroot-ai/gibson-executor/commit/2bc36f206c470f1187dedfb126aec49676dc28df))
* **ci:** move CodeQL off merge_group, fix Go extraction coverage ([#347](https://github.com/zeroroot-ai/gibson-executor/issues/347)) ([b34756f](https://github.com/zeroroot-ai/gibson-executor/commit/b34756f3bcc280b4cf5b6e81d6c91862ea557338))
* **ci:** pin Actions to SHAs, add least-privilege permissions, clear stdlib/dep CVEs ([#333](https://github.com/zeroroot-ai/gibson-executor/issues/333)) ([7348abd](https://github.com/zeroroot-ai/gibson-executor/commit/7348abd13bb2ca5aa195193049545fc2ecaee666))
* **docker:** pin base images by digest in both Dockerfiles ([#342](https://github.com/zeroroot-ai/gibson-executor/issues/342)) ([e0a3685](https://github.com/zeroroot-ai/gibson-executor/commit/e0a3685e2a530a249a96cffd1369a27522fa7b4d))
* **image:** apply distro security updates in both runtime images ([#354](https://github.com/zeroroot-ai/gibson-executor/issues/354)) ([f1aea8c](https://github.com/zeroroot-ai/gibson-executor/commit/f1aea8cb03733d9535830699934e248ea969b0a2))
* **image:** drop curl and jq from the executor runtime image ([#351](https://github.com/zeroroot-ai/gibson-executor/issues/351)) ([fd67c76](https://github.com/zeroroot-ai/gibson-executor/commit/fd67c76e1e3fc7f20dd1962ec8336771d9e162bb))
* **image:** install the five tools the catalog already advertises ([#365](https://github.com/zeroroot-ai/gibson-executor/issues/365)) ([cab8c5f](https://github.com/zeroroot-ai/gibson-executor/commit/cab8c5f68599bf3964dcf82259df4611f1388bef))
* **image:** pin runtime base digests directly on FROM, not behind ARG ([#359](https://github.com/zeroroot-ai/gibson-executor/issues/359)) ([0328015](https://github.com/zeroroot-ai/gibson-executor/commit/032801564a00f5ce2e0a86e80656197e42c5431a))
* **lint:** clear the two golangci findings in the catalog drift guard ([#367](https://github.com/zeroroot-ai/gibson-executor/issues/367)) ([fa76723](https://github.com/zeroroot-ai/gibson-executor/commit/fa767233cc260ab95116139f0fdce9020ec6d0a8))
* **mcp-bridge:** base the bridge image on official Node LTS, drop curl ([#350](https://github.com/zeroroot-ai/gibson-executor/issues/350)) ([e7334cf](https://github.com/zeroroot-ai/gibson-executor/commit/e7334cf90986abfdbb5fd14cfe54863e6c2dec7c))
* **sandbox:** stop the pre-exec helper allocating after setrlimit ([#360](https://github.com/zeroroot-ai/gibson-executor/issues/360)) ([f2ff19b](https://github.com/zeroroot-ai/gibson-executor/commit/f2ff19b0a41eda08a25402e9d9be569a69c34e50))

## [0.107.1](https://github.com/zeroroot-ai/gibson-executor/compare/v0.107.0...v0.107.1) (2026-08-07)


### Bug Fixes

* **ci:** write catalog to a workspace-relative path for oras push ([#120](https://github.com/zeroroot-ai/gibson-executor/issues/120)) ([cd85723](https://github.com/zeroroot-ai/gibson-executor/commit/cd85723b1be8bb396727118d3bfc968dd5c57dd8)), closes [#118](https://github.com/zeroroot-ai/gibson-executor/issues/118)
* **image:** build httpx/nuclei from source + bump to 1.9.0/3.11.0 to clear tool CVEs ([#123](https://github.com/zeroroot-ai/gibson-executor/issues/123)) ([a21a66f](https://github.com/zeroroot-ai/gibson-executor/commit/a21a66f70f638ae040cbc1b1fda977931d0975ea)), closes [#122](https://github.com/zeroroot-ai/gibson-executor/issues/122)
* **parsers:** validate targets and route options through the args policy ([#130](https://github.com/zeroroot-ai/gibson-executor/issues/130)) ([b801701](https://github.com/zeroroot-ai/gibson-executor/commit/b80170147637f7287890c8998a2e91a1419ab3c8))
* **sandbox:** always bound tool runs and apply RLIMIT_AS to the right process ([#132](https://github.com/zeroroot-ai/gibson-executor/issues/132)) ([8bc5a67](https://github.com/zeroroot-ai/gibson-executor/commit/8bc5a6736e6bcd3255d90ba7ac76372906218e21))

## [0.107.0](https://github.com/zeroroot-ai/gibson-executor/compare/v0.106.1...v0.107.0) (2026-06-29)


### Features

* add gibson-mcp-bridge-runner image for hosted connectors ([#86](https://github.com/zeroroot-ai/gibson-executor/issues/86)) ([75ea9bf](https://github.com/zeroroot-ai/gibson-executor/commit/75ea9bf2f6e9aa8f743f8cb4c58f13b91aff1f75))
* **mcp-bridge-runner:** consume the runtime: mcp-bridge plugin manifest ([#94](https://github.com/zeroroot-ai/gibson-executor/issues/94)) ([7f6b54e](https://github.com/zeroroot-ai/gibson-executor/commit/7f6b54eac6354609afb37fa828e0fe3baf171d3e))
* rename module and image to gibson-executor (Apache open-core E5) ([#113](https://github.com/zeroroot-ai/gibson-executor/issues/113)) ([22e2dcb](https://github.com/zeroroot-ai/gibson-executor/commit/22e2dcb48ac27ae5be064e4100b99ede530ab31d))
* sever platform-clients dependency from gibson-tool-runner ([#108](https://github.com/zeroroot-ai/gibson-executor/issues/108)) ([3a5c545](https://github.com/zeroroot-ai/gibson-executor/commit/3a5c545e41cc236f473262ecc34a6b5bfd0c857e)), closes [#98](https://github.com/zeroroot-ai/gibson-executor/issues/98)


### Bug Fixes

* **ci:** align image.yml with the working reusable-image-build caller ([#114](https://github.com/zeroroot-ai/gibson-executor/issues/114)) ([3301a34](https://github.com/zeroroot-ai/gibson-executor/commit/3301a34f0bfe117538e5954fdf1790914292a393))
* **ci:** bump go toolchain to 1.25.11 ([#78](https://github.com/zeroroot-ai/gibson-executor/issues/78)) ([7230e91](https://github.com/zeroroot-ai/gibson-executor/commit/7230e915b6c63758ff19c68a2b2fa36d2024b2a9))
* **deps:** update first-party deps to post-rename module path versions ([#64](https://github.com/zeroroot-ai/gibson-executor/issues/64)) ([dd181e5](https://github.com/zeroroot-ai/gibson-executor/commit/dd181e5856450fe7393d9f33f50741f524bc3a9f))

## [0.106.1](https://github.com/zeroroot-ai/gibson-tool-runner/compare/v0.106.0...v0.106.1) (2026-05-24)


### Bug Fixes

* **ci:** remove PR trigger and use security-extended for CodeQL ([#53](https://github.com/zeroroot-ai/gibson-tool-runner/issues/53)) ([5dc4df4](https://github.com/zeroroot-ai/gibson-tool-runner/commit/5dc4df4df4be82d8e4e1948a9d309eb04344e19d)), closes [#52](https://github.com/zeroroot-ai/gibson-tool-runner/issues/52)
* **security:** add SysProcAttr/rlimit/output-cap sandbox to child tool invocations ([#55](https://github.com/zeroroot-ai/gibson-tool-runner/issues/55)) ([39f55fa](https://github.com/zeroroot-ai/gibson-tool-runner/commit/39f55fa75de1b9e905f298e2d0d3cdf189982787))

## [0.106.0](https://github.com/zeroroot-ai/gibson-tool-runner/compare/v0.105.0...v0.106.0) (2026-05-24)


### Features

* **runner:** implement dispatch loop — decode → policy → Execute → ABI emit (closes [#33](https://github.com/zeroroot-ai/gibson-tool-runner/issues/33)) ([#44](https://github.com/zeroroot-ai/gibson-tool-runner/issues/44)) ([3e8a395](https://github.com/zeroroot-ai/gibson-tool-runner/commit/3e8a395675222e44853654ef8bd7ebc182f5e21c))

## [0.105.0](https://github.com/zeroroot-ai/gibson-tool-runner/compare/v0.104.0...v0.105.0) (2026-05-20)


### Features

* consume platform-clients for transport observability and readiness ([#29](https://github.com/zeroroot-ai/gibson-tool-runner/issues/29)) ([d740562](https://github.com/zeroroot-ai/gibson-tool-runner/commit/d7405625caa88700212c947021b4735c147bf102))

## 1.0.0 (2026-05-10)


### Features

* add CodeQL and Scorecard workflows ([#1](https://github.com/zeroroot-ai/gibson-tool-runner/issues/1)) ([886eb0e](https://github.com/zeroroot-ai/gibson-tool-runner/commit/886eb0e25061dab9bc01632a921bc971053cb901))
* install release-please and pr-title-lint ([#2](https://github.com/zeroroot-ai/gibson-tool-runner/issues/2)) ([b5883fb](https://github.com/zeroroot-ai/gibson-tool-runner/commit/b5883fbd28cd5b8bffc9f36debb2b55f75f9e777))
* per-tool args allowlist for 8 parsers + Go-CVE CI policy ([5d16fc7](https://github.com/zeroroot-ai/gibson-tool-runner/commit/5d16fc77281bd44ec07f754c7666775afa3a7f1a))


### Bug Fixes

* **deps:** bump SDK to v1.3.1, grpc to v1.81.0, docker to v28.5.2 ([e47196b](https://github.com/zeroroot-ai/gibson-tool-runner/commit/e47196bfa03ed302821a3edb0b9046324660809d))
