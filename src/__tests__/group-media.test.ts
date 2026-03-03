/**
 * Tests for MarmotGroup.encryptMedia() and MarmotGroup.decryptMedia(),
 * plus the BlobCacheStore / InMemoryKeyValueStore infrastructure.
 */

import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, randomBytes } from "@noble/hashes/utils.js";
import { defaultCryptoProvider, getCiphersuiteImpl } from "ts-mls";
import { beforeEach, describe, expect, it, vi } from "vitest";

/**
 * Creates a plain ArrayBuffer-backed Uint8Array of `n` random bytes.
 *
 * `@noble/hashes/utils` `randomBytes()` returns `Uint8Array<ArrayBufferLike>`,
 * which TypeScript rejects when used as a `BlobPart`. Wrapping with
 * `new Uint8Array(...)` forces TypeScript to accept it as `ArrayBuffer`-backed.
 */
function randomBuf(n: number): Uint8Array {
  return new Uint8Array(randomBytes(n));
}

import { BlobCacheStore } from "../client/group/blob-cache-store.js";
import { MarmotGroup } from "../client/group/marmot-group.js";
import { createCredential } from "../core/credential.js";
import { createSimpleGroup } from "../core/group.js";
import * as media from "../core/media.js";
import { generateKeyPackage } from "../core/key-package.js";
import { InMemoryKeyValueStore } from "../extra/in-memory-key-value-store.js";
import { type CachedBlob } from "../store/blob-cache-store.js";
import { GroupStateStore } from "../store/group-state-store.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

async function makeGroup(): Promise<MarmotGroup<undefined>> {
  const adminPubkey = "a".repeat(64);
  const impl = await getCiphersuiteImpl(
    "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
    defaultCryptoProvider,
  );
  const credential = createCredential(adminPubkey);
  const kp = await generateKeyPackage({ credential, ciphersuiteImpl: impl });
  const { clientState } = await createSimpleGroup(kp, impl, "Test Group", {
    adminPubkeys: [adminPubkey],
    relays: [],
  });

  // Minimal no-op store backend
  const stateBackend = {
    async get() {
      return null;
    },
    async set() {},
    async remove() {},
    async list() {
      return [];
    },
  };

  // Minimal no-op signer
  const signer = {
    async getPublicKey() {
      return adminPubkey;
    },
    async signEvent(event: any) {
      return { ...event, sig: "0".repeat(128) };
    },
  };

  // Minimal no-op network
  const network = {
    async publish() {
      return {};
    },
    async getUserInboxRelays() {
      return [];
    },
    async request() {
      return [];
    },
  };

  return new MarmotGroup(clientState, {
    ciphersuite: impl,
    stateStore: new GroupStateStore(stateBackend),
    signer: signer as any,
    network: network as any,
  });
}

// ---------------------------------------------------------------------------
// InMemoryKeyValueStore (as BlobCacheBackend)
// ---------------------------------------------------------------------------

describe("InMemoryKeyValueStore (used as BlobCacheBackend)", () => {
  it("stores and retrieves a CachedBlob", async () => {
    const backend = new InMemoryKeyValueStore<CachedBlob>();
    const data = randomBytes(32);
    const attachment: media.Mip04MediaAttachment = {
      sha256: bytesToHex(sha256(data)),
      type: "image/jpeg",
      filename: "test.jpg",
      nonce: bytesToHex(randomBytes(12)),
      version: media.MIP04_VERSION,
    };
    const entry: CachedBlob = { data, attachment };
    await backend.setItem(attachment.sha256!, entry);
    const result = await backend.getItem(attachment.sha256!);
    expect(result).toEqual(entry);
  });

  it("returns null for a missing key", async () => {
    const backend = new InMemoryKeyValueStore<CachedBlob>();
    expect(await backend.getItem("notakey")).toBeNull();
  });

  it("removes an entry", async () => {
    const backend = new InMemoryKeyValueStore<CachedBlob>();
    await backend.setItem("key", {
      data: randomBytes(8),
      attachment: {} as any,
    });
    await backend.removeItem("key");
    expect(await backend.getItem("key")).toBeNull();
  });

  it("clears all entries", async () => {
    const backend = new InMemoryKeyValueStore<CachedBlob>();
    await backend.setItem("a", { data: randomBytes(8), attachment: {} as any });
    await backend.setItem("b", { data: randomBytes(8), attachment: {} as any });
    await backend.clear();
    expect(await backend.keys()).toHaveLength(0);
  });

  it("returns all keys", async () => {
    const backend = new InMemoryKeyValueStore<CachedBlob>();
    await backend.setItem("k1", {
      data: randomBytes(4),
      attachment: {} as any,
    });
    await backend.setItem("k2", {
      data: randomBytes(4),
      attachment: {} as any,
    });
    const keys = await backend.keys();
    expect(keys.sort()).toEqual(["k1", "k2"]);
  });
});

// ---------------------------------------------------------------------------
// BlobCacheStore
// ---------------------------------------------------------------------------

describe("BlobCacheStore", () => {
  it("uses InMemoryKeyValueStore by default", async () => {
    const store = new BlobCacheStore();
    expect(await store.has("anykey")).toBe(false);
  });

  it("has() returns true after add()", async () => {
    const store = new BlobCacheStore();
    const key = bytesToHex(randomBytes(32));
    await store.add(key, { data: randomBytes(8), attachment: {} as any });
    expect(await store.has(key)).toBe(true);
  });

  it("get() returns null for missing key", async () => {
    const store = new BlobCacheStore();
    expect(await store.get("missingkey")).toBeNull();
  });

  it("remove() evicts the entry", async () => {
    const store = new BlobCacheStore();
    const key = "somekey";
    await store.add(key, { data: randomBytes(8), attachment: {} as any });
    await store.remove(key);
    expect(await store.has(key)).toBe(false);
  });

  it("clear() evicts all entries", async () => {
    const store = new BlobCacheStore();
    await store.add("a", { data: randomBytes(4), attachment: {} as any });
    await store.add("b", { data: randomBytes(4), attachment: {} as any });
    await store.clear();
    expect(await store.list()).toHaveLength(0);
  });

  it("list() returns all keys", async () => {
    const store = new BlobCacheStore();
    await store.add("x1", { data: randomBytes(4), attachment: {} as any });
    await store.add("x2", { data: randomBytes(4), attachment: {} as any });
    expect((await store.list()).sort()).toEqual(["x1", "x2"]);
  });

  it("accepts a custom backend", async () => {
    const customBackend = new InMemoryKeyValueStore<CachedBlob>();
    const store = new BlobCacheStore(customBackend);
    const key = "customkey";
    const blob: CachedBlob = {
      data: randomBytes(4),
      attachment: {} as any,
    };
    await store.add(key, blob);
    // Verify the custom backend received the write
    expect(await customBackend.getItem(key)).toEqual(blob);
  });

  it("emits blobAdded on first add", async () => {
    const store = new BlobCacheStore();
    const added: string[] = [];
    store.on("blobAdded", (key) => added.push(key));
    await store.add("sha1", { data: randomBytes(4), attachment: {} as any });
    expect(added).toEqual(["sha1"]);
  });

  it("emits blobUpdated on subsequent add with same key", async () => {
    const store = new BlobCacheStore();
    const updated: string[] = [];
    store.on("blobUpdated", (key) => updated.push(key));
    await store.add("sha1", { data: randomBytes(4), attachment: {} as any });
    await store.add("sha1", { data: randomBytes(4), attachment: {} as any });
    expect(updated).toEqual(["sha1"]);
  });

  it("emits blobRemoved on remove", async () => {
    const store = new BlobCacheStore();
    const removed: string[] = [];
    store.on("blobRemoved", (key) => removed.push(key));
    await store.add("sha1", { data: randomBytes(4), attachment: {} as any });
    await store.remove("sha1");
    expect(removed).toEqual(["sha1"]);
  });

  it("does not emit blobRemoved when key is absent", async () => {
    const store = new BlobCacheStore();
    const removed: string[] = [];
    store.on("blobRemoved", (key) => removed.push(key));
    await store.remove("notexist");
    expect(removed).toHaveLength(0);
  });

  it("emits cleared on clear()", async () => {
    const store = new BlobCacheStore();
    let clearedCount = 0;
    store.on("cleared", () => clearedCount++);
    await store.clear();
    expect(clearedCount).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// MarmotGroup.encryptMedia()
// ---------------------------------------------------------------------------

describe("MarmotGroup.encryptMedia()", () => {
  let group: MarmotGroup<undefined>;
  beforeEach(async () => {
    group = await makeGroup();
  });

  it("returns the correct attachment fields", async () => {
    const bytes = randomBuf(256);
    const blob = new Blob([bytes], { type: "image/jpeg" });
    const { attachment } = await group.encryptMedia(blob, {
      filename: "photo.jpg",
    });

    expect(attachment.version).toBe(media.MIP04_VERSION);
    expect(attachment.filename).toBe("photo.jpg");
    expect(attachment.type).toBe("image/jpeg");
    expect(attachment.sha256).toBe(bytesToHex(sha256(bytes)));
    expect(attachment.nonce).toMatch(/^[0-9a-f]{24}$/); // 12-byte hex nonce
  });

  it("uses metadata.type over blob.type when both are provided", async () => {
    const bytes = randomBuf(64);
    const blob = new Blob([bytes], { type: "image/jpeg" });
    const { attachment } = await group.encryptMedia(blob, {
      filename: "video.mp4",
      type: "video/mp4",
    });
    expect(attachment.type).toBe("video/mp4");
  });

  it("falls back to blob.type when metadata.type is omitted", async () => {
    const bytes = randomBuf(64);
    const blob = new Blob([bytes], { type: "application/octet-stream" });
    const { attachment } = await group.encryptMedia(blob, {
      filename: "data.bin",
    });
    expect(attachment.type).toBe("application/octet-stream");
  });

  it("throws when MIME type is absent from both sources", async () => {
    const blob = new Blob([randomBuf(16)]); // blob.type is ""
    await expect(
      group.encryptMedia(blob, { filename: "file.bin" }),
    ).rejects.toThrow(/MIME type/i);
  });

  it("canonicalizes the MIME type", async () => {
    const bytes = randomBuf(32);
    const blob = new Blob([bytes], { type: "IMAGE/JPEG" });
    const { attachment } = await group.encryptMedia(blob, {
      filename: "pic.jpg",
    });
    expect(attachment.type).toBe("image/jpeg");
  });

  it("preserves optional NIP-92 extras on the returned attachment", async () => {
    const bytes = randomBuf(128);
    const blob = new Blob([bytes], { type: "image/png" });
    const { attachment } = await group.encryptMedia(blob, {
      filename: "wide.png",
      dimensions: "1920x1080",
      blurhash: "LEHV6nWB2yk8pyo0adR*.7kCMdnj",
      alt: "A panoramic view",
    });
    expect(attachment.dimensions).toBe("1920x1080");
    expect(attachment.blurhash).toBe("LEHV6nWB2yk8pyo0adR*.7kCMdnj");
    expect(attachment.alt).toBe("A panoramic view");
  });

  it("uses the provided size instead of blob.size", async () => {
    const bytes = randomBuf(64);
    const blob = new Blob([bytes], { type: "image/jpeg" });
    const { attachment } = await group.encryptMedia(blob, {
      filename: "img.jpg",
      size: 99999,
    });
    expect(attachment.size).toBe(99999);
  });

  it("defaults size to blob.size when not specified", async () => {
    const bytes = randomBuf(64);
    const blob = new Blob([bytes], { type: "image/jpeg" });
    const { attachment } = await group.encryptMedia(blob, {
      filename: "img.jpg",
    });
    expect(attachment.size).toBe(bytes.byteLength);
  });

  it("encrypted output length is plaintext length + 16 (Poly1305 tag)", async () => {
    const bytes = randomBuf(100);
    const blob = new Blob([bytes], { type: "image/png" });
    const { encrypted } = await group.encryptMedia(blob, {
      filename: "test.png",
    });
    expect(encrypted.length).toBe(bytes.length + 16);
  });

  it("each call produces a unique nonce", async () => {
    const blob = new Blob([randomBuf(64)], { type: "image/jpeg" });
    const { attachment: a } = await group.encryptMedia(blob, {
      filename: "img.jpg",
    });
    const { attachment: b } = await group.encryptMedia(blob, {
      filename: "img.jpg",
    });
    expect(a.nonce).not.toBe(b.nonce);
  });
});

// ---------------------------------------------------------------------------
// MarmotGroup.decryptMedia()
// ---------------------------------------------------------------------------

describe("MarmotGroup.decryptMedia()", () => {
  let group: MarmotGroup<undefined>;
  beforeEach(async () => {
    group = await makeGroup();
  });

  it("round-trips: encrypt → decrypt produces original bytes", async () => {
    const original = randomBuf(256);
    const blob = new Blob([original], { type: "image/png" });
    const { encrypted, attachment } = await group.encryptMedia(blob, {
      filename: "snap.png",
    });

    const file = await group.decryptMedia(encrypted, attachment);
    const decrypted = new Uint8Array(await file.arrayBuffer());
    expect(decrypted).toEqual(original);
  });

  it("returned File has the correct filename", async () => {
    const bytes = randomBuf(64);
    const blob = new Blob([bytes], { type: "image/jpeg" });
    const { encrypted, attachment } = await group.encryptMedia(blob, {
      filename: "portrait.jpg",
    });
    const file = await group.decryptMedia(encrypted, attachment);
    expect(file.name).toBe("portrait.jpg");
  });

  it("returned File has the correct MIME type", async () => {
    const bytes = randomBuf(64);
    const blob = new Blob([bytes], { type: "video/mp4" });
    const { encrypted, attachment } = await group.encryptMedia(blob, {
      filename: "clip.mp4",
      type: "video/mp4",
    });
    const file = await group.decryptMedia(encrypted, attachment);
    expect(file.type).toBe("video/mp4");
  });

  it("populates the blob cache after the first decrypt", async () => {
    const bytes = randomBuf(64);
    const blob = new Blob([bytes], { type: "image/jpeg" });
    const { encrypted, attachment } = await group.encryptMedia(blob, {
      filename: "cached.jpg",
    });

    expect(await group.blobCache.has(attachment.sha256!)).toBe(false);
    await group.decryptMedia(encrypted, attachment);
    expect(await group.blobCache.has(attachment.sha256!)).toBe(true);
  });

  it("serves the second call from cache, skipping key derivation", async () => {
    const bytes = randomBuf(64);
    const blob = new Blob([bytes], { type: "image/jpeg" });
    const { encrypted, attachment } = await group.encryptMedia(blob, {
      filename: "cached.jpg",
    });

    // Spy on the low-level key derivation function
    const deriveSpy = vi.spyOn(media, "deriveMip04FileKey");

    // First call — cache miss, should call derive
    await group.decryptMedia(encrypted, attachment);
    expect(deriveSpy).toHaveBeenCalledTimes(1);

    deriveSpy.mockClear();

    // Second call — cache hit, must NOT call derive
    const file2 = await group.decryptMedia(encrypted, attachment);
    expect(deriveSpy).not.toHaveBeenCalled();

    // Content must still be correct
    const decrypted = new Uint8Array(await file2.arrayBuffer());
    expect(decrypted).toEqual(bytes);
  });

  it("emits blobAdded on the cache after decrypt", async () => {
    const bytes = randomBuf(64);
    const blob = new Blob([bytes], { type: "image/jpeg" });
    const { encrypted, attachment } = await group.encryptMedia(blob, {
      filename: "event-test.jpg",
    });

    const added: string[] = [];
    group.blobCache.on("blobAdded", (key) => added.push(key));

    await group.decryptMedia(encrypted, attachment);
    expect(added).toEqual([attachment.sha256]);
  });

  it("throws when attachment is missing sha256", async () => {
    const attachment: media.Mip04MediaAttachment = {
      sha256: undefined as any,
      type: "image/jpeg",
      filename: "bad.jpg",
      nonce: bytesToHex(randomBytes(12)),
      version: media.MIP04_VERSION,
    };
    await expect(
      group.decryptMedia(randomBytes(64), attachment),
    ).rejects.toThrow(/sha256/i);
  });

  it("throws on tampered ciphertext (AEAD failure)", async () => {
    const bytes = randomBuf(64);
    const blob = new Blob([bytes], { type: "image/jpeg" });
    const { encrypted, attachment } = await group.encryptMedia(blob, {
      filename: "tampered.jpg",
    });
    encrypted[0] ^= 0xff; // corrupt first byte
    await expect(group.decryptMedia(encrypted, attachment)).rejects.toThrow();
  });
});
