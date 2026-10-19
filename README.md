# durio-crypt — крипто-ядро E2EE dur.io

**English summary.** The end-to-end encryption core of the **dur.io** messenger: one Rust library for all clients
(Kotlin via UniFFI for Android, wasm-bindgen for the Windows client), built on matrix-sdk-crypto / vodozemac
(Olm/Megolm) behind a thin adapter for the dur.io server API. Beta: internally reviewed, no external audit.
Licensed under Apache-2.0.

Сквозное шифрование (E2EE) личных сообщений и групп в **dur.io**: одна библиотека на Rust для всех клиентов.
Автор и владелец — DakarX ([GitHub DakarXYZ](https://github.com/DakarXYZ)). Локальная папка в воркспейсе
разработки называется `stoat-crypto`, крейты — `stoat-crypto-*`.

dur.io — независимый проект на основе Stoat и не связан с ним; название и логотип Stoat — товарные знаки их
владельцев. Криптография — matrix-sdk-crypto и
vodozemac (The Matrix.org Foundation, Apache-2.0), см. [NOTICE](NOTICE).

> [!IMPORTANT]
> **Бета.** Внешнего аудита не было; код прошёл внутреннее ревью по чек-листу
> ([docs/security-review.md](docs/security-review.md)). Своей криптографии здесь нет: протокол Olm/Megolm целиком
> из matrix-sdk-crypto 0.19.1, наш код — адаптер к API сервера, защита от повтора и отката правок, привязки.

## Что внутри

| Крейт | Назначение |
| --- | --- |
| `crates/stoat-crypto` | ядро: `CryptoMachine` поверх `OlmMachine`, хранилище с ключом хоста и замком одного писателя, конверт и полезная нагрузка v1, таблицы replay и правок, вложения (AES-256-CTR, хеш до расшифровки), сверка SAS, бэкап ключей и ключ восстановления, экспорт/импорт ключей, отчёт диагностики без секретов |
| `crates/stoat-crypto-proto` | типы контракта v1: конверт, payload, тела `/e2ee/*`, события |
| `crates/stoat-crypto-ffi` | UniFFI → Kotlin, Android AAR (`bindings/android`) |
| `crates/stoat-crypto-wasm` | wasm-bindgen → npm-пакет `@durio/stoat-crypto` для Windows-клиента (`bindings/web`, ядро в Web Worker) |
| `crates/stoat-crypto-fakeserver` | сервер `/e2ee/*` в памяти для unit-, сценарных и property-тестов |
| `crates/stoat-crypto-testkit` | несколько устройств против живого бэкенда: сценарии T1–T19, нагрузка, хаос, скриптовый собеседник для e2e-тестов клиентов |

Ядро **не ходит в сеть**: оно отдаёт клиенту исходящие запросы, клиент выполняет их своим HTTP и возвращает
ответ. Поэтому одно и то же ядро работает в Android и в for-web и одинаково тестируется.

Документы:

- [docs/adr/0001-crypto-core.md](docs/adr/0001-crypto-core.md) — почему matrix-sdk-crypto, правила адаптера;
- [docs/protocol.md](docs/protocol.md) — чем протокол dur.io отличается от Matrix;
- [fixtures/](fixtures) — контракт v1 ядро↔сервер (тела, конверт, payload); меняется только новой версией;
- [docs/versioning.md](docs/versioning.md) — версии, совместимость хранилища, формат конверта;
- [docs/security-review.md](docs/security-review.md), [docs/review-checklist.md](docs/review-checklist.md) — ревью;
- [docs/load-chaos.md](docs/load-chaos.md) — нагрузка и хаос на стенде.

## Сборка

Rust 1.96.1 (`rust-toolchain.toml`), зависимости закреплены точными версиями. На Windows — всё в Docker,
скрипты сами запускают себя в закреплённом образе Rust (`scripts/dcargo.sh`, кэши в томах Docker).

```bash
cargo nextest run && cargo test --doc         # тесты (Linux), или: scripts/dcargo.sh cargo nextest run
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check
scripts/fixtures-digest.sh --check            # фикстуры контракта не изменились

scripts/build-aar.sh all                      # Android AAR (Rust + cargo-ndk + NDK r28c + JDK 21 + Android SDK)
scripts/daar.sh                               # то же на Windows в Docker
scripts/build-wasm.sh all                     # npm-пакет для for-web (инструменты качаются с проверкой SHA-256)
scripts/testkit-backend.sh up && scripts/testkit-backend.sh test   # сценарии против живого бэкенда
```

Подробности — [bindings/android/README.md](bindings/android/README.md) и
[bindings/web/README.md](bindings/web/README.md). Стенд testkit собирает бэкенд из соседнего клона
[durio-chat](https://github.com/DakarXYZ/durio-chat) (`STOATCHAT_DIR`).

## Выпуск

Одна версия на всё — версия крейтов workspace (`Cargo.toml`). Тег `vX.Y.Z`:

- `.github/workflows/aar.yml` → в GitHub Release `stoat-crypto-X.Y.Z.aar`, `.aar.sha256`, `.pom`
  (Android берёт AAR отсюда и сверяет SHA-256 с пином в `gradle/verification-metadata.xml`);
- `.github/workflows/wasm.yml` → `durio-stoat-crypto-X.Y.Z.tgz` + `.sha256` для for-web.

Текущая версия — `0.2.1`. Публикация в npm по умолчанию выключена.

Ошибки — [issues](https://github.com/DakarXYZ/durio-crypt/issues). Уязвимости — не в открытый issue: напишите
владельцу через GitHub, без деталей в публичном доступе. Никогда не прикладывайте ключи, ключ восстановления и
файлы ключей.

## Лицензия

[Apache-2.0](LICENSE). Copyright © 2026 DakarX. Сторонние компоненты и их лицензии — [NOTICE](NOTICE)
(проверяются `cargo deny`, см. `deny.toml`).
