# Контракт v1 — фикстуры (черновик заморозки, CR-01)

Сгенерированы из прототипа `spikes/spike-msc` (matrix-sdk-crypto 0.19.1 за адаптером): это ровно то, что
библиотека отправляет и принимает. Перегенерация: `DUMP_FIXTURES=1 cargo test -p spike-msc --test fixtures`
(ключи случайные, поэтому файлы меняются целиком). Без переменной тест только проверяет закоммиченные файлы.

| Файл | Что |
| --- | --- |
| `api/keys/upload.initial.json` | первый `POST /e2ee/keys/upload`: `device_keys` + 50 `one_time_keys` (**без** `fallback_keys`) |
| `api/keys/upload.otk_only.json` | второй upload: **только** `fallback_keys`, у ключа поле `"fallback": true` |
| `api/keys/query.json` | `POST /e2ee/keys/query` (ответ с пустыми `failures`/`master_keys`/`self_signing_keys`/`user_signing_keys`) |
| `api/keys/claim.json` | `POST /e2ee/keys/claim` |
| `api/keys/count.json` | `GET /e2ee/keys/count` |
| `api/to_device/put.*.json` | `PUT /e2ee/to_device/<txn_id>`: `m.room.encrypted` (Olm), `m.room_key_request` (на `"*"`), `m.key.verification.request/ready` (открытым текстом) |
| `api/to_device/get.json`, `ack.json` | ящик по C2 |
| `api/backup/*.json` | версия бэкапа и ключи (`m.megolm_backup.v1.curve25519-aes-sha2`) |
| `envelope/valid.json`, `envelope/invalid.*.json` | конверт v1 (строгий) |
| `payload/megolm_plaintext.*.json` | точный открытый текст Megolm (расшифрован vodozemac из экспортированной сессии) |
| `ws/*.json` | события WebSocket `E2eeToDevice`, `E2eeDeviceListUpdate` |
| `stores/v016/` | снимок хранилища matrix-sdk-sqlite 0.16 (схема v13) для теста миграции; ключ хранилища — 32 байта `0x42` |
| `stores/v010/` | хранилище, записанное stoat-crypto 0.1.0 (N−1 для CR-23, `tests/compat.rs`): аккаунт, сессии, таблицы CR-19, канал, ящик C2, бэкап; снимок заморожен, ключ — 32 байта `0x42` |
| `backup/recovery_key.json` | пример формата ключа восстановления (одноразовый, из спайка) |
| `backup/recovery_key.vectors.json` | ключ (32 байта, hex) → ключ восстановления; ввод с опечаткой (`typo`) и «не ключ» (`not_a_key`, вероятно пароль) (CR-12) |
| `sas/emoji.json` | таблица 64 эмодзи SAS (Matrix `sas-emoji.json`): индекс → символ, английское описание = ключ перевода (CR-11) |
| `sas/vectors.json` | 6 байт SAS (hex) → 7 индексов эмодзи и 3 десятичных числа (CR-11) |

Идентификаторы в телах `/e2ee/*` — Matrix-форма C15 (`@{lower(ulid)}:stoat.invalid`), `device_id` — ULID сессии.
В WS-событиях (это события Stoat) пользователи — ULID как есть. Расхождения с планом — `docs/spike-report.md`, §5.

## После спайка (этап 3A)

- Источник истины — эта папка. `api/` и `envelope/` побайтно скопированы в бэкенд
  (`stoatchat/crates/core/models/tests/fixtures/e2ee/`); хеши всех JSON-векторов — `SHA256SUMS`, сверка —
  `scripts/fixtures-digest.sh --check` (CI) и `--backend <путь к stoatchat>` (только `api/` и `envelope/`).
- Блок 3C: `sas/*` и `backup/*` — для тестов Kotlin/JS; перегенерация — `DUMP_FIXTURES=1 cargo test -p
  stoat-crypto --test fixtures` и `-p stoat-crypto-proto --test fixtures`.
- Типы и проверки — крейт `stoat-crypto-proto`, тест `crates/stoat-crypto-proto/tests/fixtures.rs` (круговой
  разбор каждого файла).
- `ws/E2eeToDevice.json`: `sender` исправлен на Matrix-форму (`@…:stoat.invalid`) — так его шлёт бэкенд
  (`to_device_send.rs`); в спайке там был ULID. `E2eeDeviceListUpdate.user` — ULID (событие Stoat).
- Ответ `keys/upload` у бэкенда содержит ещё `device_unused_fallback_key_types` (в фикстуре его нет — файл
  не меняем, чтобы не расходиться с копией бэкенда; поле проверяется тестом `upload_response_with_fallback_types`).
