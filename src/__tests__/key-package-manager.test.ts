import { PrivateKeyAccount } from "applesauce-accounts/accounts";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { KeyPackageManager } from "../client/key-package-manager.js";
import { KEY_PACKAGE_KIND } from "../core/protocol.js";
import {
  KeyPackageStore,
  PublishedKeyPackageRecord,
} from "../store/key-package-store.js";
import type { KeyValueStoreBackend } from "../utils/key-value.js";
import { MockNetwork } from "./helpers/mock-network.js";

// ---------------------------------------------------------------------------
// Minimal in-memory backend
// ---------------------------------------------------------------------------

class MemoryBackend<T> implements KeyValueStoreBackend<T> {
  private map = new Map<string, T>();

  async getItem(key: string): Promise<T | null> {
    return this.map.get(key) ?? null;
  }
  async setItem(key: string, value: T): Promise<T> {
    this.map.set(key, value);
    return value;
  }
  async removeItem(key: string): Promise<void> {
    this.map.delete(key);
  }
  async clear(): Promise<void> {
    this.map.clear();
  }
  async keys(): Promise<string[]> {
    return Array.from(this.map.keys());
  }
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

function makeManager(network: MockNetwork, account: PrivateKeyAccount<any>) {
  const store = new KeyPackageStore(new MemoryBackend());
  const publishedBackend = new MemoryBackend<PublishedKeyPackageRecord[]>();
  const manager = new KeyPackageManager({
    keyPackageStore: store,
    publishedKeyPackageStore: publishedBackend,
    signer: account.signer,
    network,
  });
  return { manager, store, publishedBackend };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("KeyPackageManager", () => {
  let account: PrivateKeyAccount<any>;
  let network: MockNetwork;

  beforeEach(() => {
    account = PrivateKeyAccount.generateNew();
    network = new MockNetwork(["wss://relay.test"]);
  });

  // -------------------------------------------------------------------------
  // create()
  // -------------------------------------------------------------------------

  describe("create()", () => {
    it("throws if no relays are provided", async () => {
      const { manager } = makeManager(network, account);
      await expect(manager.create({ relays: [] })).rejects.toThrow(
        "At least one relay URL is required",
      );
    });

    it("stores private key material locally", async () => {
      const { manager } = makeManager(network, account);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });

      expect(await manager.count()).toBe(1);
      expect(await manager.has(pkg.keyPackageRef)).toBe(true);
    });

    it("publishes a kind 443 event to the network", async () => {
      const { manager } = makeManager(network, account);
      await manager.create({ relays: ["wss://relay.test"] });

      const published = network.events.filter(
        (e) => e.kind === KEY_PACKAGE_KIND,
      );
      expect(published).toHaveLength(1);
    });

    it("records the published event ID in the published store", async () => {
      const { manager } = makeManager(network, account);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });

      const eventIds = await manager.getPublishedEventIds(pkg.keyPackageRef);
      expect(eventIds).toHaveLength(1);

      const published = network.events.find((e) => e.kind === KEY_PACKAGE_KIND);
      expect(eventIds[0]).toBe(published?.id);
    });

    it("records the relay URLs alongside the event ID", async () => {
      const { manager } = makeManager(network, account);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });

      const records = await manager.getPublishedEvents(pkg.keyPackageRef);
      expect(records[0].relays).toEqual(["wss://relay.test"]);
    });

    it("emits keyPackageAdded and keyPackagePublished events", async () => {
      const { manager } = makeManager(network, account);

      const added = vi.fn();
      const published = vi.fn();
      manager.on("keyPackageAdded", added);
      manager.on("keyPackagePublished", published);

      await manager.create({ relays: ["wss://relay.test"] });

      expect(added).toHaveBeenCalledOnce();
      expect(published).toHaveBeenCalledOnce();
    });

    it("accumulates multiple event IDs for the same ref via recordPublished", async () => {
      const { manager } = makeManager(network, account);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });

      await manager.recordPublished(
        pkg.keyPackageRef,
        "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233",
        ["wss://relay2.test"],
      );

      const eventIds = await manager.getPublishedEventIds(pkg.keyPackageRef);
      expect(eventIds).toHaveLength(2);
    });
  });

  // -------------------------------------------------------------------------
  // rotate()
  // -------------------------------------------------------------------------

  describe("rotate()", () => {
    it("throws if the key package ref is not found in local private store", async () => {
      const { manager } = makeManager(network, account);
      const fakeRef = new Uint8Array(32).fill(0xab);
      await expect(manager.rotate(fakeRef)).rejects.toThrow(
        "Key package not found",
      );
    });

    it("throws if no relays can be determined for the new key package", async () => {
      const { manager, store } = makeManager(network, account);

      // Add a key package to the private store without any published events
      const { generateKeyPackage } = await import("../core/key-package.js");
      const { createCredential } = await import("../core/credential.js");
      const { defaultCryptoProvider, getCiphersuiteImpl } =
        await import("ts-mls");
      const ciphersuite = await getCiphersuiteImpl(
        "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        defaultCryptoProvider,
      );
      const pubkey = await account.signer.getPublicKey();
      const kp = await generateKeyPackage({
        credential: createCredential(pubkey),
        ciphersuiteImpl: ciphersuite,
      });
      await store.add(kp);

      const listed = await manager.list();
      await expect(
        manager.rotate(listed[0].keyPackageRef, { relays: undefined }),
      ).rejects.toThrow("no relay URLs available");
    });

    it("publishes a kind 5 deletion covering all known event IDs", async () => {
      const { manager } = makeManager(network, account);

      const pkg = await manager.create({ relays: ["wss://relay.test"] });
      // Simulate a second out-of-band publish for the same ref
      await manager.recordPublished(
        pkg.keyPackageRef,
        "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233",
        ["wss://relay2.test"],
      );

      await manager.rotate(pkg.keyPackageRef);

      const deleteEvents = network.events.filter((e) => e.kind === 5);
      expect(deleteEvents).toHaveLength(1);

      const eTags = deleteEvents[0].tags.filter((t) => t[0] === "e");
      expect(eTags).toHaveLength(2);
    });

    it("creates and publishes a new kind 443 event", async () => {
      const { manager } = makeManager(network, account);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });

      await manager.rotate(pkg.keyPackageRef);

      const keyPackageEvents = network.events.filter(
        (e) => e.kind === KEY_PACKAGE_KIND,
      );
      // One from create(), one from rotate()
      expect(keyPackageEvents).toHaveLength(2);
    });

    it("removes the old private key material after rotation", async () => {
      const { manager } = makeManager(network, account);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });

      expect(await manager.count()).toBe(1);
      await manager.rotate(pkg.keyPackageRef);

      expect(await manager.count()).toBe(1);
      expect(await manager.has(pkg.keyPackageRef)).toBe(false);
    });

    it("removes the old publish records after rotation", async () => {
      const { manager } = makeManager(network, account);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });

      await manager.rotate(pkg.keyPackageRef);

      const remaining = await manager.getPublishedEventIds(pkg.keyPackageRef);
      expect(remaining).toHaveLength(0);
    });

    it("reuses relays from the old key package if no relays option is passed", async () => {
      const { manager } = makeManager(network, account);
      const pkg = await manager.create({
        relays: ["wss://specific-relay.test"],
      });

      const newPkg = await manager.rotate(pkg.keyPackageRef);

      const records = await manager.getPublishedEvents(newPkg.keyPackageRef);
      expect(records[0].relays).toContain("wss://specific-relay.test");
    });

    it("skips relay deletion if the old key package was never published", async () => {
      const { manager, store } = makeManager(network, account);

      // Add an unpublished key package directly to the private store
      const { generateKeyPackage } = await import("../core/key-package.js");
      const { createCredential } = await import("../core/credential.js");
      const { defaultCryptoProvider, getCiphersuiteImpl } =
        await import("ts-mls");
      const ciphersuite = await getCiphersuiteImpl(
        "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        defaultCryptoProvider,
      );
      const pubkey = await account.signer.getPublicKey();
      const kp = await generateKeyPackage({
        credential: createCredential(pubkey),
        ciphersuiteImpl: ciphersuite,
      });
      await store.add(kp);

      const listed = await manager.list();
      await manager.rotate(listed[0].keyPackageRef, {
        relays: ["wss://relay.test"],
      });

      const deleteEvents = network.events.filter((e) => e.kind === 5);
      expect(deleteEvents).toHaveLength(0);
    });

    it("returns a new key package with a different ref", async () => {
      const { manager } = makeManager(network, account);
      const old = await manager.create({ relays: ["wss://relay.test"] });
      const newPkg = await manager.rotate(old.keyPackageRef);

      expect(newPkg.keyPackageRef).toBeDefined();
      expect(
        Buffer.from(newPkg.keyPackageRef).equals(
          Buffer.from(old.keyPackageRef),
        ),
      ).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // remove()
  // -------------------------------------------------------------------------

  describe("remove()", () => {
    it("removes the key package from local private storage", async () => {
      const { manager } = makeManager(network, account);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });

      await manager.remove(pkg.keyPackageRef);

      expect(await manager.has(pkg.keyPackageRef)).toBe(false);
      expect(await manager.count()).toBe(0);
    });

    it("does not publish anything to the network", async () => {
      const { manager } = makeManager(network, account);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });
      const countBefore = network.events.length;

      await manager.remove(pkg.keyPackageRef);

      expect(network.events.length).toBe(countBefore);
    });

    it("emits keyPackageRemoved", async () => {
      const { manager } = makeManager(network, account);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });

      const removed = vi.fn();
      manager.on("keyPackageRemoved", removed);
      await manager.remove(pkg.keyPackageRef);

      expect(removed).toHaveBeenCalledOnce();
    });

    it("does not remove publish records (published store is independent)", async () => {
      const { manager } = makeManager(network, account);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });

      await manager.remove(pkg.keyPackageRef);

      // Published records should still exist after local removal
      const ids = await manager.getPublishedEventIds(pkg.keyPackageRef);
      expect(ids).toHaveLength(1);
    });
  });

  // -------------------------------------------------------------------------
  // purge()
  // -------------------------------------------------------------------------

  describe("purge()", () => {
    it("publishes a kind 5 deletion for a single ref", async () => {
      const { manager } = makeManager(network, account);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });

      await manager.purge(pkg.keyPackageRef);

      const deleteEvents = network.events.filter((e) => e.kind === 5);
      expect(deleteEvents).toHaveLength(1);
    });

    it("the deletion event references all known event IDs for the ref", async () => {
      const { manager } = makeManager(network, account);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });
      await manager.recordPublished(pkg.keyPackageRef, "b".repeat(64), [
        "wss://relay2.test",
      ]);

      await manager.purge(pkg.keyPackageRef);

      const deleteEvent = network.events.find((e) => e.kind === 5)!;
      const eTags = deleteEvent.tags.filter((t) => t[0] === "e");
      expect(eTags).toHaveLength(2);
    });

    it("removes publish records", async () => {
      const { manager } = makeManager(network, account);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });

      await manager.purge(pkg.keyPackageRef);

      expect(
        await manager.getPublishedEventIds(pkg.keyPackageRef),
      ).toHaveLength(0);
    });

    it("removes local private key material", async () => {
      const { manager } = makeManager(network, account);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });

      await manager.purge(pkg.keyPackageRef);

      expect(await manager.has(pkg.keyPackageRef)).toBe(false);
    });

    it("accepts an array of refs and publishes a single deletion covering all", async () => {
      const { manager } = makeManager(network, account);
      const pkg1 = await manager.create({ relays: ["wss://relay.test"] });
      const pkg2 = await manager.create({ relays: ["wss://relay2.test"] });

      await manager.purge([pkg1.keyPackageRef, pkg2.keyPackageRef]);

      const deleteEvents = network.events.filter((e) => e.kind === 5);
      // One deletion event covering both key packages
      expect(deleteEvents).toHaveLength(1);
      const eTags = deleteEvents[0].tags.filter((t) => t[0] === "e");
      expect(eTags).toHaveLength(2);
    });

    it("removes private keys and publish records for all refs in a bulk purge", async () => {
      const { manager } = makeManager(network, account);
      const pkg1 = await manager.create({ relays: ["wss://relay.test"] });
      const pkg2 = await manager.create({ relays: ["wss://relay2.test"] });

      await manager.purge([pkg1.keyPackageRef, pkg2.keyPackageRef]);

      expect(await manager.has(pkg1.keyPackageRef)).toBe(false);
      expect(await manager.has(pkg2.keyPackageRef)).toBe(false);
      expect(
        await manager.getPublishedEventIds(pkg1.keyPackageRef),
      ).toHaveLength(0);
      expect(
        await manager.getPublishedEventIds(pkg2.keyPackageRef),
      ).toHaveLength(0);
    });

    it("silently skips relay deletion for refs with no published events but still removes private key", async () => {
      const { manager, store } = makeManager(network, account);

      // Add an unpublished key package directly to the private store
      const { generateKeyPackage } = await import("../core/key-package.js");
      const { createCredential } = await import("../core/credential.js");
      const { defaultCryptoProvider, getCiphersuiteImpl } =
        await import("ts-mls");
      const ciphersuite = await getCiphersuiteImpl(
        "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        defaultCryptoProvider,
      );
      const pubkey = await account.signer.getPublicKey();
      const kp = await generateKeyPackage({
        credential: createCredential(pubkey),
        ciphersuiteImpl: ciphersuite,
      });
      await store.add(kp);
      const listed = await manager.list();
      const unpublishedRef = listed[0].keyPackageRef;

      const eventCountBefore = network.events.length;
      await manager.purge(unpublishedRef);

      expect(network.events.length).toBe(eventCountBefore);
      expect(await manager.has(unpublishedRef)).toBe(false);
    });

    it("accepts a hex string ref", async () => {
      const { manager } = makeManager(network, account);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });
      const refHex = Buffer.from(pkg.keyPackageRef).toString("hex");

      await manager.purge(refHex);

      const deleteEvents = network.events.filter((e) => e.kind === 5);
      expect(deleteEvents).toHaveLength(1);
      expect(await manager.has(refHex)).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // track()
  // -------------------------------------------------------------------------

  describe("track()", () => {
    it("returns false and ignores non-kind-443 events", async () => {
      const { manager } = makeManager(network, account);
      const result = await manager.track({
        id: "aa",
        kind: 1,
        pubkey: "bb",
        created_at: 0,
        content: "",
        tags: [],
        sig: "cc",
      });
      expect(result).toBe(false);
      expect(await manager.list()).toHaveLength(0);
    });

    it("returns false if the kind 443 event has no `i` tag", async () => {
      const { manager } = makeManager(network, account);
      const result = await manager.track({
        id: "aa",
        kind: KEY_PACKAGE_KIND,
        pubkey: "bb",
        created_at: 0,
        content: "",
        tags: [],
        sig: "cc",
      });
      expect(result).toBe(false);
      expect(await manager.list()).toHaveLength(0);
    });

    it("returns true and records the event when a valid kind 443 with `i` tag is provided", async () => {
      const { manager } = makeManager(network, account);
      const refHex = "a".repeat(64);

      const result = await manager.track({
        id: "b".repeat(64),
        kind: KEY_PACKAGE_KIND,
        pubkey: "c".repeat(64),
        created_at: 1000,
        content: "",
        tags: [
          ["i", refHex],
          ["relays", "wss://relay.test"],
        ],
        sig: "d".repeat(128),
      });

      expect(result).toBe(true);
      const records = await manager.getPublishedEvents(refHex);
      expect(records).toHaveLength(1);
      expect(records[0].eventId).toBe("b".repeat(64));
    });

    it("records relay URLs from the event's relays tag", async () => {
      const { manager } = makeManager(network, account);
      const refHex = "a".repeat(64);

      await manager.track({
        id: "b".repeat(64),
        kind: KEY_PACKAGE_KIND,
        pubkey: "c".repeat(64),
        created_at: 1000,
        content: "",
        tags: [
          ["i", refHex],
          ["relays", "wss://relay1.test", "wss://relay2.test"],
        ],
        sig: "d".repeat(128),
      });

      const records = await manager.getPublishedEvents(refHex);
      // relay URLs are normalised (trailing slash added) by getKeyPackageRelays
      expect(records[0].relays).toEqual([
        "wss://relay1.test/",
        "wss://relay2.test/",
      ]);
    });

    it("records a key package event even when we have no private key for it", async () => {
      const { manager } = makeManager(network, account);
      // This ref is for a key package from another device — not in private store
      const foreignRef = "f".repeat(64);

      const result = await manager.track({
        id: "e".repeat(64),
        kind: KEY_PACKAGE_KIND,
        pubkey: "c".repeat(64),
        created_at: 1000,
        content: "",
        tags: [["i", foreignRef]],
        sig: "d".repeat(128),
      });

      expect(result).toBe(true);
      // Not in private store
      expect(await manager.has(foreignRef)).toBe(false);
      // But is in published store
      const records = await manager.getPublishedEvents(foreignRef);
      expect(records).toHaveLength(1);
    });

    it("tracked event is queryable via getPublishedEvents()", async () => {
      const { manager } = makeManager(network, account);
      const refHex = "a".repeat(64);

      await manager.track({
        id: "b".repeat(64),
        kind: KEY_PACKAGE_KIND,
        pubkey: "c".repeat(64),
        created_at: 1000,
        content: "",
        tags: [["i", refHex]],
        sig: "d".repeat(128),
      });

      const records = await manager.getPublishedEvents(refHex);
      expect(records).toHaveLength(1);
      expect(records[0].eventId).toBe("b".repeat(64));
    });

    it("emits keyPackagePublished when a valid event is tracked", async () => {
      const { manager } = makeManager(network, account);
      const refHex = "a".repeat(64);
      const eventId = "b".repeat(64);

      const publishedHandler = vi.fn();
      manager.on("keyPackagePublished", publishedHandler);

      await manager.track({
        id: eventId,
        kind: KEY_PACKAGE_KIND,
        pubkey: "c".repeat(64),
        created_at: 1000,
        content: "",
        tags: [["i", refHex]],
        sig: "d".repeat(128),
      });

      expect(publishedHandler).toHaveBeenCalledOnce();
      expect(publishedHandler).toHaveBeenCalledWith(refHex, eventId, []);
    });

    it("accumulates multiple events for the same ref", async () => {
      const { manager } = makeManager(network, account);
      const refHex = "a".repeat(64);

      await manager.track({
        id: "b".repeat(64),
        kind: KEY_PACKAGE_KIND,
        pubkey: "c".repeat(64),
        created_at: 1000,
        content: "",
        tags: [["i", refHex]],
        sig: "d".repeat(128),
      });
      await manager.track({
        id: "e".repeat(64),
        kind: KEY_PACKAGE_KIND,
        pubkey: "c".repeat(64),
        created_at: 2000,
        content: "",
        tags: [["i", refHex]],
        sig: "d".repeat(128),
      });

      const ids = await manager.getPublishedEventIds(refHex);
      expect(ids).toHaveLength(2);
    });
  });

  // -------------------------------------------------------------------------
  // recordPublished()
  // -------------------------------------------------------------------------

  describe("recordPublished()", () => {
    it("adds a publish record for any ref (does not require local private key)", async () => {
      const { manager } = makeManager(network, account);
      const foreignRef = "f".repeat(64);

      await manager.recordPublished(foreignRef, "a".repeat(64), [
        "wss://relay.test",
      ]);

      const ids = await manager.getPublishedEventIds(foreignRef);
      expect(ids).toHaveLength(1);
    });

    it("accumulates multiple records for the same ref", async () => {
      const { manager } = makeManager(network, account);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });

      await manager.recordPublished(pkg.keyPackageRef, "b".repeat(64), [
        "wss://relay2.test",
      ]);
      await manager.recordPublished(pkg.keyPackageRef, "c".repeat(64), [
        "wss://relay3.test",
      ]);

      const ids = await manager.getPublishedEventIds(pkg.keyPackageRef);
      // One from create(), plus two manual records
      expect(ids).toHaveLength(3);
    });
  });

  // -------------------------------------------------------------------------
  // list()
  // -------------------------------------------------------------------------

  describe("list()", () => {
    it("returns all locally stored key packages enriched with publish records", async () => {
      const { manager } = makeManager(network, account);
      await manager.create({ relays: ["wss://relay.test"] });
      await manager.create({ relays: ["wss://relay.test"] });

      expect(await manager.list()).toHaveLength(2);
    });

    it("each entry includes publishedEvents — filter for published packages", async () => {
      const { manager, store } = makeManager(network, account);

      // One published package
      await manager.create({ relays: ["wss://relay.test"] });

      // One unpublished package (added directly to private store, no publish record)
      const { generateKeyPackage } = await import("../core/key-package.js");
      const { createCredential } = await import("../core/credential.js");
      const { defaultCryptoProvider, getCiphersuiteImpl } =
        await import("ts-mls");
      const ciphersuite = await getCiphersuiteImpl(
        "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        defaultCryptoProvider,
      );
      const pubkey = await account.signer.getPublicKey();
      const kp = await generateKeyPackage({
        credential: createCredential(pubkey),
        ciphersuiteImpl: ciphersuite,
      });
      await store.add(kp);

      const all = await manager.list();
      expect(all).toHaveLength(2);
      expect(all.filter((p) => p.publishedEvents.length > 0)).toHaveLength(1);
    });

    it("tracked foreign ref (no private key) does not appear in list()", async () => {
      const { manager } = makeManager(network, account);

      // Track a key package from another device — no private key locally
      const foreignRef = "f".repeat(64);
      await manager.track({
        id: "b".repeat(64),
        kind: KEY_PACKAGE_KIND,
        pubkey: "c".repeat(64),
        created_at: 1000,
        content: "",
        tags: [["i", foreignRef]],
        sig: "d".repeat(128),
      });

      // list() is snapshot-based — only local private keys appear
      expect(await manager.list()).toHaveLength(0);
      // But it is queryable directly
      const records = await manager.getPublishedEvents(foreignRef);
      expect(records).toHaveLength(1);
    });
  });

  // -------------------------------------------------------------------------
  // getPublishedEvents()
  // -------------------------------------------------------------------------

  describe("getPublishedEvents()", () => {
    it("returns empty array for an unknown ref", async () => {
      const { manager } = makeManager(network, account);
      const fakeRef = new Uint8Array(32).fill(0xcd);
      expect(await manager.getPublishedEvents(fakeRef)).toEqual([]);
    });

    it("returns all records with correct shape", async () => {
      const { manager } = makeManager(network, account);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });

      const records = await manager.getPublishedEvents(pkg.keyPackageRef);
      expect(records).toHaveLength(1);
      expect(records[0]).toMatchObject({
        eventId: expect.any(String),
        relays: ["wss://relay.test"],
        publishedAt: expect.any(Number),
      });
    });
  });

  // -------------------------------------------------------------------------
  // watchKeyPackages()
  // -------------------------------------------------------------------------

  describe("watchKeyPackages()", () => {
    it("yields initial snapshot immediately", async () => {
      const { manager } = makeManager(network, account);
      await manager.create({ relays: ["wss://relay.test"] });

      const gen = manager.watchKeyPackages();
      const { value } = await gen.next();
      await gen.return(undefined);

      expect(value).toHaveLength(1);
      expect(value[0].publishedEvents).toHaveLength(1);
    });

    it("initial snapshot includes publishedEvents merged from published backend", async () => {
      const { manager } = makeManager(network, account);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });

      const gen = manager.watchKeyPackages();
      const { value } = await gen.next();
      await gen.return(undefined);

      expect(value[0].keyPackageRef).toEqual(pkg.keyPackageRef);
      expect(value[0].publishedEvents).toHaveLength(1);
      expect(value[0].publishedEvents[0].relays).toContain("wss://relay.test");
    });

    it("yields updated snapshot after a key package is added", async () => {
      const { manager } = makeManager(network, account);
      const gen = manager.watchKeyPackages();

      // Consume initial empty snapshot
      const first = await gen.next();
      expect(first.value).toHaveLength(0);

      // Create a package — should trigger a new yield
      const created = manager.create({ relays: ["wss://relay.test"] });
      const second = await gen.next();
      await created; // ensure create() completes
      await gen.return(undefined);

      expect(second.value).toHaveLength(1);
    });

    it("yields updated snapshot after a publish is recorded", async () => {
      const { manager } = makeManager(network, account);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });

      const gen = manager.watchKeyPackages();
      // Consume initial snapshot (1 published event)
      await gen.next();

      // Record another publish — should trigger a new yield
      const record = manager.recordPublished(
        pkg.keyPackageRef,
        "b".repeat(64),
        ["wss://relay2.test"],
      );
      const { value } = await gen.next();
      await record;
      await gen.return(undefined);

      expect(value[0].publishedEvents).toHaveLength(2);
    });

    it("yields updated snapshot after a key package is removed", async () => {
      const { manager } = makeManager(network, account);
      const pkg = await manager.create({ relays: ["wss://relay.test"] });

      const gen = manager.watchKeyPackages();
      // Consume initial snapshot
      await gen.next();

      const removal = manager.remove(pkg.keyPackageRef);
      const { value } = await gen.next();
      await removal;
      await gen.return(undefined);

      expect(value).toHaveLength(0);
    });
  });
});
