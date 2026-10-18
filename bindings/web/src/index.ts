// @durio/stoat-crypto — the dur.io crypto core (matrix-sdk-crypto 0.19.1 behind our
// adapter, CR-14) for for-web inside the Windows client. This entry is page-side only and
// never loads the wasm: the wasm lives in the crypto worker (`@durio/stoat-crypto/worker`).

export {
  AttachmentDecryptor,
  AttachmentEncryptor,
  AttachmentVerifier,
  BackupRestore,
  SasFlow,
  StoatCrypto,
} from "./client.js";
export { StoatCryptoError, isStoatCryptoError, type StoatCryptoErrorCode } from "./errors.js";
export { lockName, storeName } from "./names.js";
export type { Endpoint } from "./rpc.js";
export type * from "./types.js";

import { lockName as accountLock } from "./names.js";

/**
 * Whether another window or worker holds the account's crypto lock (the UI shows
 * "Encryption is active in another window"). `open` itself also refuses with `StoreLocked`.
 */
export async function isAccountLocked(accountKey: string): Promise<boolean> {
  const name = accountLock(accountKey);
  const state = await navigator.locks.query();
  return (state.held ?? []).some((l) => l.name === name);
}
