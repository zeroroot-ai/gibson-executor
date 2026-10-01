# Changelog

## [0.111.0](https://github.com/zeroroot-ai/gibson-executor/compare/v0.110.3...v0.111.0) (2026-10-01)


### Features

* **go:** move the toolchain floor to 1.27.1 ([#91](https://github.com/zeroroot-ai/gibson-executor/issues/91)) ([6e3f942](https://github.com/zeroroot-ai/gibson-executor/commit/6e3f9427dcbe7c15abda3f627d81abfd1d7a29fc))
* **tools:** add kube-bench, the CIS policies benchmark ([#86](https://github.com/zeroroot-ai/gibson-executor/issues/86)) ([eb1a20b](https://github.com/zeroroot-ai/gibson-executor/commit/eb1a20b5f470e50c6c9d9bbd00b58b218a747bb9))
* **trivy:** fail the build when trivy's linked dependencies move ([#46](https://github.com/zeroroot-ai/gibson-executor/issues/46)) ([3df2d67](https://github.com/zeroroot-ai/gibson-executor/commit/3df2d6789e65294f91518c10dddea7f6b2092573))


### Bug Fixes

* **ci:** link-check checks only the Markdown a PR touched (.github v0.7.2) ([#82](https://github.com/zeroroot-ai/gibson-executor/issues/82)) ([52bf8ee](https://github.com/zeroroot-ai/gibson-executor/commit/52bf8ee03ef1c444d9a21a91eeee6fd6ac571a8c))
* **ci:** pin every zeroroot-ai/.github reference to v0.5.1 ([#53](https://github.com/zeroroot-ai/gibson-executor/issues/53)) ([f348481](https://github.com/zeroroot-ai/gibson-executor/commit/f3484819bca9ccc33f75a0a29aa6a2c31b93ae20))
* **ci:** pin the org tree guards to a commit SHA ([#38](https://github.com/zeroroot-ai/gibson-executor/issues/38)) ([b3b386d](https://github.com/zeroroot-ai/gibson-executor/commit/b3b386d7112ec867833ea0e25b96dfa9ad7fb6c9))
* **ci:** unbreak the image build ([#44](https://github.com/zeroroot-ai/gibson-executor/issues/44)) ([de852ec](https://github.com/zeroroot-ai/gibson-executor/commit/de852ec92d26bbf15f6483c81bc50b9b22cae6ae))
* **image:** apt-get upgrade was cached, so it only ever ran once ([#45](https://github.com/zeroroot-ai/gibson-executor/issues/45)) ([049cbdc](https://github.com/zeroroot-ai/gibson-executor/commit/049cbdcdccc778f64d35642a62b24cac2ea2b7e4))
* **image:** build trivy from source with a grpc floor so the image publishes again ([#70](https://github.com/zeroroot-ai/gibson-executor/issues/70)) ([7ca94c8](https://github.com/zeroroot-ai/gibson-executor/commit/7ca94c84dbf428bb1e926f69823c44cc288091ae)), closes [#69](https://github.com/zeroroot-ai/gibson-executor/issues/69)
* **image:** ship the license text inside the published image ([#42](https://github.com/zeroroot-ai/gibson-executor/issues/42)) ([2467d53](https://github.com/zeroroot-ai/gibson-executor/commit/2467d5392245b4e0a2ef169943ccb22be1190bac))
* **policy:** a denied flag keeps its value even when it starts with a dash ([#55](https://github.com/zeroroot-ai/gibson-executor/issues/55)) ([6fdf818](https://github.com/zeroroot-ai/gibson-executor/commit/6fdf81883546dc4cfde95a52be1087ac314809d4))
* **policy:** a value attached to a flag no longer hides it from the policy ([#54](https://github.com/zeroroot-ai/gibson-executor/issues/54)) ([4936202](https://github.com/zeroroot-ai/gibson-executor/commit/4936202c2c0b4c4ed4b43ba2a04755a3458f20bd))

## Changelog

This repository restarted from a fresh baseline on 2026-09-06. Release notes before that date are archived offline and do not resolve on GitHub. release-please adds each release below this line.
