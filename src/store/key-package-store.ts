import { bytesToHex } from "@noble/hashes/utils.js";
import { CryptoProvider, defaultCryptoProvider } from "ts-mls";
import { KeyPackage, PrivateKeyPackage } from "ts-mls/keyPackage.js";
import { calculateKeyPackageRef } from "../core/key-package.js";
import { KeyValueStoreBackend } from "../utils/key-value.js";
import { EventEmitter } from "eventemitter3";

/**
 * A single publish record for a key package — one entry per kind 443 Nostr event.
 *
 * Multiple records can exist for the same key package ref if the same key package
 * was published more than once (e.g. to different relay sets or by different devices).
 */
export type PublishedKeyPackageRecord = {
  /** The Nostr event ID of the kind 443 event */
  eventId: string;
  /** The relay URLs this event was published to */
  relays: string[];
  /** Unix timestamp (seconds) when this record was created locally */
  publishedAt: number;
};

/**
 * Backend type for the published key package store.
 *
 * Keys are keyPackageRef hex strings. Values are arrays of publish records.
 * Apps can implement this with any storage engine (localForage, IndexedDB,
 * in-memory Map, etc.) by satisfying the {@link KeyValueStoreBackend} interface.
 *
 * @example
 * ```typescript
 * // Using an in-memory backend
 * const backend: PublishedKeyPackageStoreBackend = new MemoryBackend();
 * const manager = new KeyPackageManager({ ..., publishedKeyPackageStore: backend });
 * ```
 */
export type PublishedKeyPackageStoreBackend = KeyValueStoreBackend<
  PublishedKeyPackageRecord[]
>;

export type StoredKeyPackage = {
  /** The calculated key package reference (should be used to identify the key package) */
  keyPackageRef: Uint8Array;
  /** The public key package */
  publicPackage: KeyPackage;
  /** The private key package */
  privatePackage: PrivateKeyPackage;
};

/** A type for listing the key package without the private package */
export type ListedKeyPackage = Omit<StoredKeyPackage, "privatePackage">;

/** Backend interface for the key package store */
export interface KeyPackageStoreBackend extends KeyValueStoreBackend<StoredKeyPackage> {}

/** Options for creating a {@link KeyPackageStore} instance */
export type KeyPackageStoreOptions = {
  /** The crypto provider to use for cryptographic operations */
  cryptoProvider?: CryptoProvider;
};

type KeyPackageStoreEvents = {
  /** Emitted when a key package is added */
  keyPackageAdded: (keyPackage: StoredKeyPackage) => void;
  /** Emitted when a key package is removed */
  keyPackageRemoved: (keyPackageRef: Uint8Array) => void;
};

/**
 * Stores key packages in a {@link KeyPackageStoreBackend}.
 *
 * Manages private key material only — publish tracking is handled separately
 * by {@link PublishedKeyPackageStore}.
 *
 * @example
 * ```typescript
 * const store = new KeyPackageStore(backend);
 *
 * // Add a complete key package
 * await store.add({ publicPackage, privatePackage });
 * // List all key packages
 * const packages = await store.list();
 * // Get a specific key package by its ref
 * const privatePackage = await store.getPrivateKey(ref);
 * // Remove a key package
 * await store.remove(ref);
 * ```
 */
export class KeyPackageStore extends EventEmitter<KeyPackageStoreEvents> {
  private backend: KeyPackageStoreBackend;
  private readonly cryptoProvider: CryptoProvider;

  /**
   * Creates a new KeyPackageStore instance.
   * @param backend - The storage backend to use (e.g., localForage)
   * @param options - Options for the store
   */
  constructor(
    backend: KeyPackageStoreBackend,
    { cryptoProvider }: KeyPackageStoreOptions = {},
  ) {
    super();
    this.backend = backend;
    this.cryptoProvider = cryptoProvider ?? defaultCryptoProvider;
  }

  /**
   * Resolves the storage key from various input types.
   * @param hashOrPackage - The hash or key package to resolve
   */
  private async resolveStorageKey(
    hashOrPackage: Uint8Array | string | KeyPackage,
  ): Promise<string> {
    if (typeof hashOrPackage === "string") {
      return hashOrPackage;
    }
    if (hashOrPackage instanceof Uint8Array) {
      return bytesToHex(hashOrPackage);
    }
    return bytesToHex(
      await calculateKeyPackageRef(hashOrPackage, this.cryptoProvider),
    );
  }

  /** Ensures that a stored key package object has a key package reference */
  private async ensureKeyPackageRef<T extends { publicPackage: KeyPackage }>(
    keyPackage: T,
  ): Promise<T & { keyPackageRef: Uint8Array }> {
    if (
      "keyPackageRef" in keyPackage &&
      keyPackage.keyPackageRef instanceof Uint8Array
    )
      return keyPackage as T & { keyPackageRef: Uint8Array };

    return {
      ...keyPackage,
      keyPackageRef: await calculateKeyPackageRef(
        keyPackage.publicPackage,
        this.cryptoProvider,
      ),
    };
  }

  /**
   * Adds a complete key package to the store.
   *
   * @param keyPackage - The complete key package containing both public and private components
   * @returns A promise that resolves to the storage key used
   */
  async add(
    keyPackage: Omit<StoredKeyPackage, "keyPackageRef">,
  ): Promise<string> {
    const key = await this.resolveStorageKey(keyPackage.publicPackage);

    const serialized: StoredKeyPackage = {
      keyPackageRef: await calculateKeyPackageRef(
        keyPackage.publicPackage,
        this.cryptoProvider,
      ),
      publicPackage: keyPackage.publicPackage,
      privatePackage: keyPackage.privatePackage,
    };

    await this.backend.setItem(key, serialized);

    const stored = await this.ensureKeyPackageRef(serialized);
    this.emit("keyPackageAdded", stored);

    return key;
  }

  /**
   * Retrieves only the public key package from the store.
   *
   * @param ref - The key package reference (as Uint8Array or hex string) or the public key package
   * @returns A promise that resolves to the public key package, or null if not found
   */
  async getPublicKey(
    ref: Uint8Array | string | KeyPackage,
  ): Promise<KeyPackage | null> {
    const key = await this.resolveStorageKey(ref);
    const stored = await this.backend.getItem(key);
    return stored ? stored.publicPackage : null;
  }

  /**
   * Retrieves only the private key package from the store.
   *
   * Use this method when you need access to the private keys for cryptographic operations.
   * Be cautious about keeping private keys in memory longer than necessary.
   *
   * @param ref - The key package reference (as Uint8Array or hex string) or the public key package
   */
  async getPrivateKey(
    ref: Uint8Array | string | KeyPackage,
  ): Promise<PrivateKeyPackage | null> {
    const key = await this.resolveStorageKey(ref);
    const stored = await this.backend.getItem(key);
    return stored ? stored.privatePackage : null;
  }

  /**
   * Retrieves the complete key package (both public and private) from the store.
   *
   * @param ref - The key package reference (as Uint8Array or hex string) or the public key package
   * @returns A promise that resolves to the complete key package, or null if not found
   */
  async getKeyPackage(
    ref: Uint8Array | string | KeyPackage,
  ): Promise<StoredKeyPackage | null> {
    const key = await this.resolveStorageKey(ref);
    const stored = await this.backend.getItem(key);
    return stored && (await this.ensureKeyPackageRef(stored));
  }

  /**
   * Removes a key package from the store.
   * @param ref - The key package reference (as Uint8Array or hex string) or the public key package
   */
  async remove(ref: Uint8Array | string | KeyPackage): Promise<void> {
    const key = await this.resolveStorageKey(ref);
    const stored = await this.backend.getItem(key);
    await this.backend.removeItem(key);

    if (stored) {
      const withRef = await this.ensureKeyPackageRef(stored);
      this.emit("keyPackageRemoved", withRef.keyPackageRef);
    }
  }

  /**
   * Lists all key packages stored in the store (without private material).
   * @returns An array of listed key packages
   */
  async list(): Promise<ListedKeyPackage[]> {
    const allKeys = await this.backend.keys();

    const packages = await Promise.all(
      allKeys.map((key) =>
        this.backend
          .getItem(key)
          .then((pkg) => pkg && this.ensureKeyPackageRef(pkg)),
      ),
    );

    return packages
      .filter((pkg) => pkg !== null)
      .map((pkg) => ({
        keyPackageRef: pkg.keyPackageRef,
        publicPackage: pkg.publicPackage,
      }));
  }

  /** Gets the count of key packages stored. */
  async count(): Promise<number> {
    const packages = await this.list();
    return packages.length;
  }

  /** Clears all key packages from the store. */
  async clear(): Promise<void> {
    const allKeys = await this.backend.keys();
    for (const key of allKeys) {
      const stored = await this.backend.getItem(key);
      await this.backend.removeItem(key);
      if (stored) {
        const withRef = await this.ensureKeyPackageRef(stored);
        this.emit("keyPackageRemoved", withRef.keyPackageRef);
      }
    }
  }

  /**
   * Checks if a key package exists in the store.
   * @param ref - The key package reference (as Uint8Array or hex string) or the public key package
   */
  async has(ref: Uint8Array | string | KeyPackage): Promise<boolean> {
    const key = await this.resolveStorageKey(ref);
    const item = await this.backend.getItem(key);
    return item !== null;
  }
}
