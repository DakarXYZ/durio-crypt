# Контракт v1 — фикстуры (черновик заморозки, CR-01)

Сгенерированы из прототипа `crates/spike-msc` (matrix-sdk-crypto 0.19.1 за адаптером): это ровно то, что
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
| `backup/recovery_key.json` | пример формата ключа восстановления (одноразовый) |

Идентификаторы в телах `/e2ee/*` — Matrix-форма C15 (`@{lower(ulid)}:stoat.invalid`), `device_id` — ULID сессии.
В WS-событиях (это события Stoat) пользователи — ULID как есть. Расхождения с планом — `docs/spike-report.md`, §5.
