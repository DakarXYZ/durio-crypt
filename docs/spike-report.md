# Спайк CR-01: matrix-sdk-crypto против своего слоя на vodozemac — отчёт

Дата: 2026-10-17. Окружение: Docker `rust:1.96.1-bookworm`, Windows 11 хост. Решение — `docs/adr/0001-crypto-core.md`.

## 1. Что собрано

| Путь | Что |
| --- | --- |
| `crates/spike-msc` | прототип адаптера над `OlmMachine` (`client.rs`, прообраз CR-20 + CR-19), fakeserver (`fakeserver.rs`, прообраз CR-18), C15 (`ids.rs`), конверт/payload v1 (`payload.rs`); тесты `tests/scenarios.rs` (S1–S12), `tests/migration.rs` (0.16 → 0.19), `tests/fixtures.rs` (контракт v1) |
| `crates/spike-vodozemac` | мини-слой на vodozemac 0.11.1 только для S1 и S4, тот же fakeserver |
| `tools/store-016` | отдельный workspace: снимок хранилища matrix-sdk-sqlite 0.16 |
| `tools/size-probe` | обёртка для замеров wasm и Android `.so` |
| `fixtures/` | черновик контракта v1 |

Версии (точные пины): `matrix-sdk-crypto =0.19.1` (фича только `automatic-room-key-forwarding`),
`matrix-sdk-sqlite =0.19.1` (`crypto-store`, `bundled`), `matrix-sdk-common =0.19.1`, `ruma =0.17.0`,
`vodozemac =0.11.1`; тулчейн `1.96.1` (MSRV 0.19.1 = 1.96 — проверено на crates.io).

Запуск: `scripts/dcargo.sh cargo test --workspace` (реестр, target и rustup — в именованных томах Docker,
`CARGO_BUILD_JOBS=4`).

## 2. Матрица сценариев

Все тесты — без патчей библиотеки. «Адаптер» = наш код в `client.rs`.

| # | Тест | Итог | Что показано / оговорки |
| --- | --- | --- | --- |
| S1 = T1 | `s01_dm_roundtrip_only_ciphertext_on_server` | ✅ | В «БД» только конверт v1 из 5 полей; payload кратен 256 байт; отправитель читает своё эхо (CR-24) без пометки replay |
| S2 = T2 | `s02_new_device_sees_only_new_messages` | ✅ | Старое — `MissingRoomKey`; запрос ключа непроверенным устройством остаётся без ответа; новое от B и от A1 читается (B узнаёт A2 по `E2eeDeviceListUpdate`) |
| S3 = T3 | `s03_backup_restore_with_recovery_key` | ✅ | `m.megolm_backup.v1.curve25519-aes-sha2`, recovery key base58 (48 символов); импорт 2 сессий; все сообщения — `Unauthenticated`; неверный ключ отвергнут до записи |
| S4 = T4/T5 | `s04_removed_member_and_removed_device_rotate` | ✅ | Выход участника и удаление устройства → новая `session_id`; удалённые получают `MissingRoomKey` |
| S5 = T6 | `s05_new_member_reads_only_new` | ✅ | Добавление без ротации (та же сессия); D читает с текущего индекса, старое — `MissingRoomKey` |
| S6 = T7 | `s06_lost_room_key_recovered_from_own_verified_device` | ✅ | Сервер потерял `m.room_key` → авто-`m.room_key_request` на `"*"` → проверенное своё устройство пересылает; непроверенное (B3) — не получает. Ключ помечен `Unauthenticated` (пересланный) |
| S7 = T8/T16/T17 | `s07_tamper_room_author_replay_edit_reply` | ✅ | Перенос в другой канал → `MissingRoomKey` (см. §5.6); подмена автора → `Mismatch` (`VerificationLevel::MismatchedSender`); подмена `device_id` → `Mismatch` (наш слой); повтор под новым id → `is_replay`; откат правки → `stale_edit`; подмена `replies` → `reply_mismatch`; порча шифротекста → `Corrupted`; `v=2`/чужой алгоритм → `UnsupportedVersion`/`UnknownAlgorithm` |
| S8 = T12 | `s08_sas_emoji_both_sides_verified` | ✅ | `request → ready → start → accept → key → mac → done` через to_device; 7 эмодзи и десятичные совпали; без кросс-подписания `SignatureUpload` не создаётся; оба устройства `is_verified()`, щит адаптера → `Verified` |
| S9 = T13 | `s09_otk_exhausted_fallback_then_replenish` | ✅ | OTK на сервере 0 → claim отдаёт fallback → сессия создана, сообщение прочитано, OTK дозагружены до 50. **Fallback не ротируется по факту использования** (см. §5.2) |
| S10 | `s10_restart_mid_send_no_index_reuse` | ✅ | SQLite: зашифровали (индекс 1), «упали» до отправки, открыли заново → следующее сообщение индекс 2, ключи аккаунта те же |
| S11 | `s11_two_processes_same_store_cross_process_lock` | ⚠️ частично | Библиотека **не мешает** открыть вторую `OlmMachine` на том же файле. `CrossProcessLock` работает: второй держатель — `Busy`, после освобождения получает замок, первый при повторном захвате видит `Dirty`. Освобождение не мгновенное (понадобился `spin_lock`). Вывод: замок — opt-in; от двух писателей защищаемся сами (файловый lock CR-17) |
| S12 = T19 | `s12_crash_between_processing_and_ack` | ✅ | Множество обработанных id хранится **атомарно** с изменениями крипто-хранилища через `next_batch_token`; после рестарта повтор отброшен до `receive_sync_changes`, ошибок Olm нет, `m.dummy` к A не ушёл |
| S12b | `s12b_control_without_filter_library_detects_replay` | ✅ (контроль) | Без нашего фильтра повтор Olm-сообщения даёт UTD `DecryptionFailure` (внутри — `OlmError::ReplayedMessage`, библиотека узнаёт повтор по хешу), `m.dummy` не отправляется. Фильтр C2 оставляем: без него каждый повтор — ложная ошибка в логах/метриках |
| C8 | `payload_v1_attachment_encrypted_file_v2` | ✅ | `EncryptedFile` v2 из `AttachmentEncryptor`, младшие 64 бита IV нулевые, спойлер, расшифровка с проверкой хеша |
| Крит. 4 | `store_016_migrates_to_019` | ✅ | Снимок 0.16 (схема v13) открывается 0.19.1 (v19): ключи аккаунта те же, входящая Megolm-сессия расшифровывает, `next_batch_token` сохранён |
| Контракт | `contract_v1_fixtures` | ✅ | Фикстуры сгенерированы и проверяются |

Итого: 16 тестов в `spike-msc` + 1 юнит, 2 теста в `spike-vodozemac`; все зелёные. S11 выражается без патчей,
но ожидание «второй ждёт или получает ошибку» библиотека сама не обеспечивает.

T9 (старый клиент), T11 (push), T14 (мульти-сервер), T15, T18 — не про ядро (сервер/клиенты), в спайке не
проверялись. T10 — частично (формат и шифрование вложения; autumn/crond — нет).

## 3. Объём кода

Строки без пустых и комментариев (`grep -cvE '^\s*(//|$)'`):

| Что | Строк | Покрытие |
| --- | --- | --- |
| Адаптер на matrix-sdk-crypto: `client.rs` + `ids.rs` + `payload.rs` | 585 + 36 + 63 = **684** | S1–S12, бэкап, SAS-обвязка, replay/правки/ответы (CR-19), щит, C2 с атомарным множеством, конверт v1 |
| Свой слой на vodozemac: `spike-vodozemac/src/lib.rs` | **388** | только S1 и S4: аккаунт, подписи, канонический JSON (упрощённый), claim OTK, Olm в обе стороны, Megolm, ротация по составу, проверки привязки Olm, author/room при расшифровке |
| Fakeserver (общий) | 561 | — |
| Тесты: сценарии / фикстуры / миграция / общие | 558 / 282 / 45 / 53 | — |

Чего нет в своём слое (всё есть в matrix-sdk-crypto и уже проверено в S2–S12): хранилище и миграции,
пополнение OTK, fallback, отслеживание устройств и «грязные» пользователи, залечивание Olm и защита от повтора
Olm, запросы/пересылка ключей, SAS, бэкап, withheld, ротация по времени/счётчику, конкурентность, `RoomKeyInfo`.
Для S1+S4 объёмы сопоставимы (≈350–400 строк адаптера приходится на те же S1+S4 — в основном JSON-обвязка), но дальше адаптер растёт на ~50 строк
на сценарий, а свой слой — на сотни (оценка плана: 93 против 59 дн. на этап 3).

Оценка боевого адаптера (CR-20 + CR-19 + типы FFI, персистентная таблица replay, ошибки): 1,5–2,5 тыс. строк —
в пределах ориентира 3 тыс. (критерий 6).

## 4. Замеры

Сборка `tools/size-probe` (обёртка-диспетчер, держащая достижимым весь API, которым пользуется адаптер:
upload/query/claim/to_device/backup, `receive_sync_changes`, `share_room_key`, encrypt/decrypt, SAS, бэкап,
вложения). Профиль: `opt-level="z"`, `lto="fat"`, `codegen-units=1`, `strip="symbols"`; без `qrcode` и
`experimental-*`. Скрипты: `tools/size-probe/measure-wasm.sh`, `measure-android.sh` (Docker, NDK r28c).

| Артефакт | Сырой | После обработки | gzip -9 | brotli -q11 | Бюджет C23 |
| --- | --- | --- | --- | --- | --- |
| wasm, память (без хранилища), `wasm-bindgen 0.2.129 --target web` | 2 078 067 Б | `wasm-opt -Oz` (binaryen 123): **1 946 238 Б** | **753 977 Б (0,72 МБ)** | 581 135 Б | ≤ 3 МБ gzip ✅ |
| wasm + `matrix-sdk-indexeddb` | 2 794 213 Б | **2 615 363 Б** | **985 216 Б (0,94 МБ)** | 738 484 Б | ≤ 3 МБ gzip ✅ |
| Android arm64 `.so`, без SQLite | — | stripped **2 876 856 Б (2,74 МБ)** | 1 559 863 Б | — | ≤ 12 МБ ✅ |
| Android arm64 `.so` + `matrix-sdk-sqlite` (bundled SQLite) | — | stripped **5 518 088 Б (5,26 МБ)** | 2 947 829 Б | — | ≤ 12 МБ ✅ |

Оговорки: (1) в обёртке нет UniFFI-скаффолдинга и наших типов FFI — боевой `.so` будет больше (оценка +0,5–1,5 МБ;
не измерено). (2) Эталон плана (Element `libmatrix_sdk_crypto_ffi.so` ≈ 11,6 МБ stripped, wasm Element 2,10 МБ
gzip) собран с `qrcode`, полным FFI и не под `opt-level="z"` — поэтому наши цифры в 2–4 раза меньше. (3) ELF
выровнен на 16 КБ (`LOAD align 0x4000`, NDK r28c) — требование Android 15+ выполнено. (4) Android-сборка —
`panic = "unwind"` (как требует CR-02), wasm — `panic = "abort"`.

Не измерено: холодный `open` с 10 000 сессий, расшифровка 100 сообщений, пиковая память на Android — нужен
эмулятор/устройство; перенесено в CR-02/CR-17.

## 5. Находки, важные для контракта v1 и бэкенда

1. **Fallback-ключи (BE-04/BE-06).** Первый `keys/upload` несёт `device_keys` + 50 OTK **без** `fallback_keys`.
   Fallback приходит **отдельным** `keys/upload`, где есть только `fallback_keys`, а у ключа — поле
   `"fallback": true` (`fixtures/api/keys/upload.otk_only.json`). Библиотека создаёт fallback, только если в
   ответе `keys/count` **есть** `device_unused_fallback_key_types` (пустой массив = «сервер поддерживает, свободных
   нет»). Поле обязательно всегда. Ротация fallback — **по возрасту (неделя)**, а не по признаку «использован»:
   сервер обязан отдавать использованный fallback в `claim` повторно, пока клиент его не заменит, и не удалять его
   при claim.
2. **`keys/upload` без `device_keys`** — штатный случай (только OTK или только fallback). Повтор `device_keys` с тем
   же содержимым — 200, с другим — 409 (C22).
3. **`keys/query` без кросс-подписания.** Ответ с пустыми `master_keys`/`self_signing_keys`/`user_signing_keys`
   библиотека принимает. Посторонние поля (`failed` в ответе `PUT /to_device`, Q11) ruma игнорирует.
4. **Ящик.** Тело `GET /e2ee/to_device` → `{messages:[{id, sender, sender_device, type, content}]}`; `sender` — в
   Matrix-форме C15 (адаптер передаёт его библиотеке как есть), `sender_device` — ULID. `type` в HTTP-теле (C3),
   `event_type` — только в WS. `m.room_key_request` и сообщения SAS ходят **открытым текстом** (не
   `m.room.encrypted`) — сервер не должен требовать шифрования to_device. `m.room_key_request` шлётся на `"*"`.
5. **Порядок обработки to_device.** Если `m.room_key` и запрос ключа на эту сессию пришли в одной пачке
   `receive_sync_changes`, запрос обрабатывается до сохранения ключа и теряется («unknown session»). Адаптер
   подаёт события **по одному** (CR-05 «по одному» подтверждено). Каждое событие — своя транзакция; заодно
   множество обработанных id (C2) коммитится вместе с изменениями через `next_batch_token` — атомарно, без патча.
6. **Перенос сообщения в другой канал** даёт `MissingRoomKey`, а не `MismatchedRoom`: сессии ищутся по
   `(room_id, session_id)`. Безопасно (не показывается), но для UI это «ожидание ключа», и библиотека шлёт
   бесполезный запрос ключа своим устройствам. `MismatchedRoom` возможен только при расхождении `room_id` внутри
   открытого текста.
7. **Конверт v1.** Библиотека выдаёт `{algorithm, ciphertext, session_id, sender_key, device_id}`; мы отбрасываем
   `sender_key` (Q5) — расшифровка без него работает. Открытый текст Megolm — ровно `{type, room_id, content}`
   (`fixtures/payload/megolm_plaintext.full.json`), C7 подтверждён.
8. **Доверие.** Без кросс-подписания библиотека относит всех отправителей к `UnsignedDevice`; результат SAS
   (локальное доверие устройству) в `EncryptionInfo` не виден — щит считает адаптер (`get_device().is_verified()`).
   Нужны `TrustRequirement::Untrusted` и `CollectStrategy::AllDevices` (MSC4153-режим требует кросс-подписания →
   v1.1). Ключи из бэкапа и пересланные — `Unauthenticated` (адаптер проверяет `has_been_imported()` /
   `forwarder_data`).
9. **Отслеживание.** Библиотека игнорирует запрос верификации от пользователя, которого не отслеживает, и не может
   связать сессию с устройством неизвестного автора. Адаптер обязан держать в `tracked_users` всех участников
   зашифрованных каналов и себя (`set_channel_members`), а также вызывать `get_missing_sessions(∅)` после каждого
   прохода синхронизации (иначе ответы на запросы ключей и залечивание не получают Olm-сессию).
10. **Бэкап.** `auth_data` = `{public_key, signatures: {}}` (подписей нет без кросс-подписания); тело `PUT
    /e2ee/backup/keys?version=` — Matrix `{rooms:{room:{sessions:{session:KeyBackupData}}}}`, ответ `{etag, count}`
    (etag — строка). Версия передаётся query-параметром.
11. **API библиотеки меняется.** 0.16 → 0.19: `OlmMachine::with_store` заменён на `OlmMachineBuilder`,
    `import_backed_up_room_keys` объявлен устаревшим, в ruma 0.17 `try_from_http_response` переехал в
    `IncomingResponseExt`. Обновление раз в квартал — 0,5–1 дн. правок адаптера.

## 6. Открытые вопросы

- Таблица replay и `edit_seq` в спайке в памяти; в ядре — персистентно (своя таблица в нашем SQLite или
  `custom_value` хранилища) — решить в CR-09/CR-19.
- `CrossProcessLock`: освобождение по истечении аренды; для Android всё равно нужен файловый замок (CR-17).
- Холодный старт FCM-сервиса (CR-17, ≤ 10 с) и память — замерить на устройстве.
- `matrix-sdk-indexeddb` собран под wasm32 (§4), но в браузере не запускался — WEB/CR-14.
- Шум запросов ключей при переносе сообщения сервером (§5.6) — можно гасить: не запрашивать ключ, если
  `session_id` известен нам в другом канале.
