# Changelog

## 1.0.0 (2026-10-22)


### ⚠ BREAKING CHANGES

* **oauth:** Microsoft accounts are reported with EmailVerified=false unless the ID token proves verification (configure the xms_edov optional claim). GitHub accounts whose primary email is unverified are reported unverified.

### Features

* add anon plugin ([71e21c3](https://github.com/WebDeveloperBen/BetterAuthGoServer/commit/71e21c38a6926dda6253373730ce5afaa28131aa))
* add api plugin ([647e299](https://github.com/WebDeveloperBen/BetterAuthGoServer/commit/647e299cd41259b833acbb45174ee391f4ad2689))
* add azure provider ([3b6b625](https://github.com/WebDeveloperBen/BetterAuthGoServer/commit/3b6b625103122838c07f775d50f6a24cc12bc554))
* add deviceauth plugin ([aa7474c](https://github.com/WebDeveloperBen/BetterAuthGoServer/commit/aa7474c39b396ea84bcf8cbd78afc21c943945fa))
* add global hooks,jwt, kv, otel,admin ([9ed905a](https://github.com/WebDeveloperBen/BetterAuthGoServer/commit/9ed905a60d55b93fe93ad6a698c65c7652ad39be))
* add migrations and update examples ([13cfd78](https://github.com/WebDeveloperBen/BetterAuthGoServer/commit/13cfd785944443ab8c354f0c5676b878549272f8))
* add mysql support ([904b6f3](https://github.com/WebDeveloperBen/BetterAuthGoServer/commit/904b6f31c721f4559b0d583c081e4a3359e4c98e))
* add mysql support via adapter pattern ([d8cbe8f](https://github.com/WebDeveloperBen/BetterAuthGoServer/commit/d8cbe8fbc08d6769238a1436fc371959d2789f19))
* add plugin chaining support along with function calls ([d84d5f8](https://github.com/WebDeveloperBen/BetterAuthGoServer/commit/d84d5f8be14590a65fe480e7b0d203239b49bf2d))
* add tests for webauthn impl ([6f46ad6](https://github.com/WebDeveloperBen/BetterAuthGoServer/commit/6f46ad652b3f4e90709de84b2a8ea0f3cb04f32f))
* create OTP plugin ([1dd1776](https://github.com/WebDeveloperBen/BetterAuthGoServer/commit/1dd177692e40b62a0ef7656efba7ecd1b72903df))
* implement jwks for jwt keys ([95002ff](https://github.com/WebDeveloperBen/BetterAuthGoServer/commit/95002ff076afaf75ac6901045b3b273560d50aa7))
* implement organisations and fix admins ([ba11cdf](https://github.com/WebDeveloperBen/BetterAuthGoServer/commit/ba11cdf98ff24cc20abb9e5423c6c04298a5cff7))
* refactor things and add webauthn plugin ([ddb5eee](https://github.com/WebDeveloperBen/BetterAuthGoServer/commit/ddb5eee9845d8e3b055a50eec9f403468c3ff99a))
* refactor to use sqlc for plugins ([717742d](https://github.com/WebDeveloperBen/BetterAuthGoServer/commit/717742d5464ae5417182df9ed9672360a527e2cd))
* remove bun and now ready for plugin ownage ([801c36c](https://github.com/WebDeveloperBen/BetterAuthGoServer/commit/801c36c589e1e501ec9eaede2eb3669a78293809))
* running passing tests for all three dialects in parallel ([28a4e07](https://github.com/WebDeveloperBen/BetterAuthGoServer/commit/28a4e07e6314685fc206080eb72e7bfb7d8f1f9a))
* write base library ([97e2dce](https://github.com/WebDeveloperBen/BetterAuthGoServer/commit/97e2dcecc89408207079a1a613f40657bbc362e9))
* write nuxt integration client and fix bugs in anon and org plugins ([fec71cc](https://github.com/WebDeveloperBen/BetterAuthGoServer/commit/fec71cc00a1a2c2c00ba2e53b6877ade0f620cbb))


### Bug Fixes

* **ci:** ci pipelines to now use mise tooling ([29ea14b](https://github.com/WebDeveloperBen/BetterAuthGoServer/commit/29ea14b731e1da13db8b94a60c898b7982a93b5a))
* **ci:** remove go mode install for golangci-lint ([2d9ba86](https://github.com/WebDeveloperBen/BetterAuthGoServer/commit/2d9ba8666ddbe7eea63ea2f1d01bc4969226a3b8))
* **ci:** scope unit tests to only run unit tests ([9f21422](https://github.com/WebDeveloperBen/BetterAuthGoServer/commit/9f214223c4488dca867f034ef062d7d98d27c9f3))
* **ci:** update workflow pages ([0d944f3](https://github.com/WebDeveloperBen/BetterAuthGoServer/commit/0d944f327f12f0bee46cb958c73c561ac5980f1d))
* **ci:** use v9 golangci-lint not v6 ([ff57364](https://github.com/WebDeveloperBen/BetterAuthGoServer/commit/ff573649b84d5c54992a0127a42eb472fbf0046a))
* create auth response interface to handle responses cleanly ([1115841](https://github.com/WebDeveloperBen/BetterAuthGoServer/commit/1115841cf8121de8d5e93d3e63ea65faca30716d))
* lint ci version ([30cc9bf](https://github.com/WebDeveloperBen/BetterAuthGoServer/commit/30cc9bffad7ba7cbed6a21d472bc80ea23d40d45))
* **oauth:** safe account linking, GitLab provider and release tooling ([#2](https://github.com/WebDeveloperBen/BetterAuthGoServer/issues/2)) ([9feb7c0](https://github.com/WebDeveloperBen/BetterAuthGoServer/commit/9feb7c030f95504b65ad252cf68580d274b87819))
* tests to reuse docker containers with truncating ([8077fa0](https://github.com/WebDeveloperBen/BetterAuthGoServer/commit/8077fa0a2d3051de7b3fd3a98e87f63e6a45aed1))
