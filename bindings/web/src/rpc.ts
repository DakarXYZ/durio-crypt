// A small typed RPC over postMessage (50-web-sdk, cross-cutting decision 3): request
// ids, one answer per request, errors as {code, message}, Transferables both ways. No
// dependency; works over a dedicated Worker, its global scope or a MessagePort.

import { type ErrorInfo, StoatCryptoError, isStoatCryptoError } from "./errors.js";

/** Worker, DedicatedWorkerGlobalScope or MessagePort */
export interface Endpoint {
  postMessage(message: unknown, transfer: Transferable[]): void;
  addEventListener(type: "message", listener: (event: MessageEvent) => void): void;
  start?(): void;
}

export interface RpcRequest {
  id: number;
  method: string;
  args: unknown[];
}

export type RpcResponse = { id: number; ok: true; value: unknown } | { id: number; ok: false; error: ErrorInfo };

/** The worker cannot answer any more (a wasm trap outside a call): every call fails */
export interface RpcFatal {
  fatal: ErrorInfo;
}

/** A result (or argument) that moves its buffers instead of copying them */
export class Transfer<T> {
  constructor(
    readonly value: T,
    readonly transfer: Transferable[],
  ) {}
}

export function transfer<T>(value: T, list: Transferable[]): Transfer<T> {
  return new Transfer(value, list);
}

/** Page side: `call` resolves with the worker's value or rejects with a StoatCryptoError */
export class RpcClient {
  #next = 1;
  #pending = new Map<number, { resolve(v: unknown): void; reject(e: Error): void }>();
  #closed: ErrorInfo | null = null;

  constructor(private readonly endpoint: Endpoint) {
    endpoint.addEventListener("message", (event) => this.#answer(event.data as RpcResponse | RpcFatal));
    endpoint.start?.();
  }

  call<T>(method: string, args: unknown[] = [], transferList: Transferable[] = []): Promise<T> {
    if (this.#closed) return Promise.reject(toError(this.#closed));
    const id = this.#next++;
    return new Promise<T>((resolve, reject) => {
      this.#pending.set(id, { resolve: resolve as (v: unknown) => void, reject });
      try {
        this.endpoint.postMessage({ id, method, args } satisfies RpcRequest, transferList);
      } catch {
        this.#pending.delete(id);
        reject(new StoatCryptoError("InvalidInput", "argument cannot be sent to the worker"));
      }
    });
  }

  /** Fail every pending and later call (worker terminated or crashed) */
  close(error: ErrorInfo = { code: "WorkerClosed", message: "the crypto worker is closed" }): void {
    this.#closed = error;
    for (const p of this.#pending.values()) p.reject(toError(error));
    this.#pending.clear();
  }

  #answer(r: RpcResponse | RpcFatal): void {
    if (r && "fatal" in r) return this.close(r.fatal);
    const p = this.#pending.get(r?.id);
    if (!p) return;
    this.#pending.delete(r.id);
    if (r.ok) p.resolve(r.value);
    else p.reject(toError(r.error));
  }
}

function toError(e: ErrorInfo): StoatCryptoError {
  return new StoatCryptoError(e.code, e.message);
}

export type Handler = (...args: never[]) => unknown;

/**
 * Worker side: answer requests with `handlers[method](...args)`. A thrown
 * StoatCryptoError (ours or the wasm's) keeps its code and fixed message; anything
 * else becomes `Internal` without its message (it might quote data). `onError` may
 * replace the answer (the worker turns a wasm trap into `Panic`).
 */
export function serve(
  endpoint: Endpoint,
  handlers: Record<string, Handler>,
  onError: (e: unknown) => ErrorInfo | null = () => null,
): void {
  endpoint.addEventListener("message", async (event) => {
    const { id, method, args } = event.data as RpcRequest;
    let response: RpcResponse;
    let list: Transferable[] = [];
    try {
      const handler = Object.hasOwn(handlers, method) ? handlers[method] : undefined;
      if (!handler) throw new StoatCryptoError("InvalidInput", "unknown method");
      let value = await (handler as (...a: unknown[]) => unknown)(...(Array.isArray(args) ? args : []));
      if (value instanceof Transfer) {
        list = value.transfer;
        value = value.value;
      }
      response = { id, ok: true, value };
    } catch (e) {
      response = { id, ok: false, error: onError(e) ?? errorInfo(e) };
    }
    endpoint.postMessage(response, list);
  });
  endpoint.start?.();
}

export function errorInfo(e: unknown): ErrorInfo {
  if (isStoatCryptoError(e)) return { code: e.code, message: e.message };
  const name = typeof e === "object" && e !== null && "name" in e ? String(e.name) : typeof e;
  return { code: "Internal", message: `internal crypto error (${name})` };
}
