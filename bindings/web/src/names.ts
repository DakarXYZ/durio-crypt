// Names derived from the accountKey (00-architecture §6: sha256(canonicalApiUrl + "\n" +
// user_id), truncated): one IndexedDB store and one Web Lock per account and server.
// No `@` in the store name: for-web's sign-out cleanup deletes `@…` databases (WEB-03).

import { StoatCryptoError } from "./errors.js";

/** Prefix of the IndexedDB databases (`<name>::matrix-sdk-crypto`, `…-meta`) */
export function storeName(accountKey: string): string {
  return `durio-e2ee-${checked(accountKey)}`;
}

/** Web Lock held by the worker while the machine is open (Q28) */
export function lockName(accountKey: string): string {
  return `durio-e2ee:${checked(accountKey)}`;
}

function checked(accountKey: string): string {
  if (typeof accountKey !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(accountKey)) {
    throw new StoatCryptoError("InvalidInput", "invalid input: accountKey must be 1-128 of [A-Za-z0-9_-]");
  }
  return accountKey;
}
