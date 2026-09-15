// P08-00 Vault compatibility freeze: test-only fixture I/O. Never imported by runtime code.
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";

export const VAULT_COMPAT_FIXTURE_DIR = path.resolve(import.meta.dirname, "../fixtures/vault-compat");

export const VAULT_COMPAT_FILES = Object.freeze({
  snapshot: "vault-snapshot.v1.json",
  expectedRecords: "vault-snapshot.v1.expected-records.json",
  encryptedBackup: "encrypted-backup.v1.openarc",
  logicalBackup: "logical-backup.v1.json",
  opaqueRescue: "opaque-rescue.v1.json",
} as const);

export interface IndexedDbStoreImage {
  name: string;
  keyPath: string;
  autoIncrement: boolean;
  rows: unknown[];
}

/** A raw IndexedDB image: exactly what the browser persists, with no parsing applied. */
export interface IndexedDbImage {
  database: { name: string; version: number };
  stores: IndexedDbStoreImage[];
}

export interface VaultCompatManifest {
  packet: "P08-00";
  warning: string;
  integrationCommit: string;
  generator: string;
  command: string;
  secrets: { workspacePassphrase: string; recoverySecret: string; backupPassphrase: string };
  recordCountsByKind: Record<string, number>;
  receiptSchemas: string[];
  files: Record<string, { bytes: number; sha256: string }>;
}

export function sha256Hex(bytes: Uint8Array | string): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export async function readFixtureText(name: string): Promise<string> {
  return readFile(path.join(VAULT_COMPAT_FIXTURE_DIR, name), "utf8");
}

export async function readFixtureJson<T>(name: string): Promise<T> {
  return JSON.parse(await readFixtureText(name)) as T;
}

export async function readManifest(): Promise<VaultCompatManifest> {
  return readFixtureJson<VaultCompatManifest>("manifest.json");
}

export function requestResult<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("IndexedDB request failed"));
  });
}

export function transactionDone(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error ?? new Error("IndexedDB transaction failed"));
    transaction.onabort = () => reject(transaction.error ?? new Error("IndexedDB transaction aborted"));
  });
}

/** Opens the named database without a version, so no upgrade is ever triggered. */
function openExisting(name: string): Promise<IDBDatabase | null> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(name);
    request.onupgradeneeded = () => {
      request.transaction?.abort();
      resolve(null);
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => {
      if (request.error?.name === "AbortError") resolve(null);
      else reject(request.error ?? new Error("IndexedDB open failed"));
    };
  });
}

export async function readIndexedDbImage(name: string): Promise<IndexedDbImage | null> {
  const db = await openExisting(name);
  if (!db) return null;
  try {
    const names = Array.from(db.objectStoreNames).sort();
    if (names.length === 0) return { database: { name: db.name, version: db.version }, stores: [] };
    const transaction = db.transaction(names, "readonly");
    const stores = await Promise.all(names.map(async (storeName) => {
      const store = transaction.objectStore(storeName);
      const keyPath = store.keyPath;
      if (typeof keyPath !== "string") throw new Error(`Unexpected keyPath for ${storeName}`);
      return { name: storeName, keyPath, autoIncrement: store.autoIncrement,
        rows: await requestResult<unknown[]>(store.getAll()) };
    }));
    await transactionDone(transaction);
    return { database: { name: db.name, version: db.version }, stores };
  } finally {
    db.close();
  }
}

/** Writes a frozen raw image byte-for-byte into fake IndexedDB, bypassing every Vault parser. */
export async function seedIndexedDbImage(image: IndexedDbImage): Promise<void> {
  const db = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open(image.database.name, image.database.version);
    request.onupgradeneeded = () => {
      for (const store of image.stores) {
        request.result.createObjectStore(store.name, { keyPath: store.keyPath, autoIncrement: store.autoIncrement });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("IndexedDB seed open failed"));
  });
  try {
    const transaction = db.transaction(image.stores.map((store) => store.name), "readwrite");
    for (const store of image.stores) {
      for (const row of store.rows) transaction.objectStore(store.name).put(structuredClone(row));
    }
    await transactionDone(transaction);
  } finally {
    db.close();
  }
}

export function deleteIndexedDb(name: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.deleteDatabase(name);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error ?? new Error("IndexedDB deletion failed"));
    request.onblocked = () => reject(new Error("Test database deletion was blocked"));
  });
}

export function storeRows(image: IndexedDbImage, name: string): unknown[] {
  const store = image.stores.find((candidate) => candidate.name === name);
  if (!store) throw new Error(`Fixture image has no ${name} store`);
  return store.rows;
}
