import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, randomBytes } from "@noble/hashes/utils.js";
import { defaultCryptoProvider, getCiphersuiteImpl } from "ts-mls";
import { describe, expect, it } from "vitest";

import { createCredential } from "../core/credential.js";
import { generateKeyPackage } from "../core/key-package.js";
import { createSimpleGroup } from "../core/group.js";
import {
  canonicalizeMimeType,
  decryptMediaFile,
  deriveMip04FileKey,
  encryptMediaFile,
  MIP04_VERSION,
  type Mip04MediaAttachment,
} from "../core/media.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function makeClientState() {
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
  return { clientState, ciphersuite: impl };
}

/** Build a minimal valid Mip04MediaAttachment for a given file. */
function makeAttachment(
  file: Uint8Array,
  mimeType = "image/jpeg",
  filename = "photo.jpg",
): Mip04MediaAttachment {
  return {
    sha256: bytesToHex(sha256(file)),
    type: mimeType,
    filename,
    nonce: "",
    version: MIP04_VERSION,
  };
}

// ---------------------------------------------------------------------------
// canonicalizeMimeType
// ---------------------------------------------------------------------------

describe("canonicalizeMimeType", () => {
  it("lowercases the type", () => {
    expect(canonicalizeMimeType("IMAGE/JPEG")).toBe("image/jpeg");
  });

  it("trims whitespace", () => {
    expect(canonicalizeMimeType("  image/jpeg  ")).toBe("image/jpeg");
  });

  it("strips parameters", () => {
    expect(canonicalizeMimeType("image/jpeg; charset=utf-8")).toBe(
      "image/jpeg",
    );
  });

  it("handles combined cases", () => {
    expect(canonicalizeMimeType("  TEXT/PLAIN ; charset=US-ASCII  ")).toBe(
      "text/plain",
    );
  });

  it("leaves a clean mime type unchanged", () => {
    expect(canonicalizeMimeType("video/mp4")).toBe("video/mp4");
  });
});

// ---------------------------------------------------------------------------
// deriveMip04FileKey
// ---------------------------------------------------------------------------

describe("deriveMip04FileKey", () => {
  it("returns 32 bytes", async () => {
    const { clientState, ciphersuite } = await makeClientState();
    const key = await deriveMip04FileKey(
      clientState,
      ciphersuite,
      makeAttachment(randomBytes(100)),
    );
    expect(key).toBeInstanceOf(Uint8Array);
    expect(key.length).toBe(32);
  });

  it("is deterministic for the same epoch + file metadata", async () => {
    const { clientState, ciphersuite } = await makeClientState();
    const attachment = makeAttachment(randomBytes(100));
    const a = await deriveMip04FileKey(clientState, ciphersuite, attachment);
    const b = await deriveMip04FileKey(clientState, ciphersuite, attachment);
    expect(bytesToHex(a)).toBe(bytesToHex(b));
  });

  it("produces different keys for different file hashes", async () => {
    const { clientState, ciphersuite } = await makeClientState();
    const keyA = await deriveMip04FileKey(
      clientState,
      ciphersuite,
      makeAttachment(randomBytes(100)),
    );
    const keyB = await deriveMip04FileKey(
      clientState,
      ciphersuite,
      makeAttachment(randomBytes(100)),
    );
    expect(bytesToHex(keyA)).not.toBe(bytesToHex(keyB));
  });

  it("produces different keys for different MIME types", async () => {
    const { clientState, ciphersuite } = await makeClientState();
    const file = randomBytes(100);
    const keyA = await deriveMip04FileKey(
      clientState,
      ciphersuite,
      makeAttachment(file, "image/jpeg"),
    );
    const keyB = await deriveMip04FileKey(
      clientState,
      ciphersuite,
      makeAttachment(file, "video/mp4"),
    );
    expect(bytesToHex(keyA)).not.toBe(bytesToHex(keyB));
  });

  it("produces different keys for different filenames", async () => {
    const { clientState, ciphersuite } = await makeClientState();
    const file = randomBytes(100);
    const keyA = await deriveMip04FileKey(
      clientState,
      ciphersuite,
      makeAttachment(file, "image/jpeg", "photo.jpg"),
    );
    const keyB = await deriveMip04FileKey(
      clientState,
      ciphersuite,
      makeAttachment(file, "image/jpeg", "other.jpg"),
    );
    expect(bytesToHex(keyA)).not.toBe(bytesToHex(keyB));
  });

  it("canonicalizes MIME type before key derivation", async () => {
    const { clientState, ciphersuite } = await makeClientState();
    const file = randomBytes(100);
    const keyLower = await deriveMip04FileKey(
      clientState,
      ciphersuite,
      makeAttachment(file, "image/jpeg"),
    );
    const keyUpper = await deriveMip04FileKey(
      clientState,
      ciphersuite,
      makeAttachment(file, "IMAGE/JPEG"),
    );
    const keyParams = await deriveMip04FileKey(
      clientState,
      ciphersuite,
      makeAttachment(file, "image/jpeg; charset=utf-8"),
    );
    expect(bytesToHex(keyLower)).toBe(bytesToHex(keyUpper));
    expect(bytesToHex(keyLower)).toBe(bytesToHex(keyParams));
  });

  it("throws when sha256 is missing", async () => {
    const { clientState, ciphersuite } = await makeClientState();
    const attachment = {
      type: "image/jpeg",
      filename: "photo.jpg",
    } as unknown as Mip04MediaAttachment;
    await expect(
      deriveMip04FileKey(clientState, ciphersuite, attachment),
    ).rejects.toThrow("sha256");
  });

  it("throws when type is missing", async () => {
    const { clientState, ciphersuite } = await makeClientState();
    const attachment = {
      sha256: bytesToHex(sha256(randomBytes(32))),
      filename: "photo.jpg",
    } as unknown as Mip04MediaAttachment;
    await expect(
      deriveMip04FileKey(clientState, ciphersuite, attachment),
    ).rejects.toThrow("type");
  });
});

// ---------------------------------------------------------------------------
// encryptMediaFile / decryptMediaFile
// ---------------------------------------------------------------------------

describe("encryptMediaFile / decryptMediaFile", () => {
  it("round-trips a small file", async () => {
    const { clientState, ciphersuite } = await makeClientState();
    const file = new Uint8Array([10, 20, 30, 40, 50]);
    const attachment = makeAttachment(
      file,
      "application/octet-stream",
      "data.bin",
    );

    const fileKey = await deriveMip04FileKey(
      clientState,
      ciphersuite,
      attachment,
    );
    const { encrypted, attachment: filled } = encryptMediaFile(
      file,
      fileKey,
      attachment,
    );
    expect(decryptMediaFile(encrypted, fileKey, filled)).toEqual(file);
  });

  it("round-trips a larger file", async () => {
    const { clientState, ciphersuite } = await makeClientState();
    const file = randomBytes(16384);
    const attachment = makeAttachment(file, "image/png", "large.png");

    const fileKey = await deriveMip04FileKey(
      clientState,
      ciphersuite,
      attachment,
    );
    const { encrypted, attachment: filled } = encryptMediaFile(
      file,
      fileKey,
      attachment,
    );
    expect(decryptMediaFile(encrypted, fileKey, filled)).toEqual(file);
  });

  it("populated attachment has correct fields", async () => {
    const { clientState, ciphersuite } = await makeClientState();
    const file = randomBytes(64);
    const attachment = makeAttachment(file, "image/jpeg", "img.jpg");

    const fileKey = await deriveMip04FileKey(
      clientState,
      ciphersuite,
      attachment,
    );
    const { attachment: filled } = encryptMediaFile(file, fileKey, attachment);

    expect(filled.version).toBe(MIP04_VERSION);
    expect(filled.nonce).toMatch(/^[0-9a-f]{24}$/); // 12 bytes hex-encoded
    expect(filled.sha256).toBe(attachment.sha256);
    expect(filled.type).toBe("image/jpeg");
    expect(filled.filename).toBe("img.jpg");
  });

  it("canonicalizes the MIME type on the returned attachment", async () => {
    const { clientState, ciphersuite } = await makeClientState();
    const file = randomBytes(32);
    const attachment = makeAttachment(file, "IMAGE/JPEG", "img.jpg");

    const fileKey = await deriveMip04FileKey(
      clientState,
      ciphersuite,
      attachment,
    );
    const { attachment: filled } = encryptMediaFile(file, fileKey, attachment);
    expect(filled.type).toBe("image/jpeg");
  });

  it("each encryption produces a unique nonce", async () => {
    const { clientState, ciphersuite } = await makeClientState();
    const file = randomBytes(64);
    const attachment = makeAttachment(file);

    const fileKey = await deriveMip04FileKey(
      clientState,
      ciphersuite,
      attachment,
    );
    const { attachment: a } = encryptMediaFile(file, fileKey, attachment);
    const { attachment: b } = encryptMediaFile(file, fileKey, attachment);
    expect(a.nonce).not.toBe(b.nonce);
  });

  it("encrypted length is plaintext length + 16 (Poly1305 tag)", async () => {
    const { clientState, ciphersuite } = await makeClientState();
    const file = randomBytes(100);
    const attachment = makeAttachment(
      file,
      "application/octet-stream",
      "test.bin",
    );

    const fileKey = await deriveMip04FileKey(
      clientState,
      ciphersuite,
      attachment,
    );
    const { encrypted } = encryptMediaFile(file, fileKey, attachment);
    expect(encrypted.length).toBe(file.length + 16);
  });

  it("extra FileMetadata fields are preserved on the returned attachment", async () => {
    const { clientState, ciphersuite } = await makeClientState();
    const file = randomBytes(32);
    const attachment: Mip04MediaAttachment = {
      ...makeAttachment(file),
      url: "https://example.com/blob",
      dimensions: "800x600",
      blurhash: "LEHV6nWB2yk8pyo0adR*.7kCMdnj",
      alt: "A test image",
    };

    const fileKey = await deriveMip04FileKey(
      clientState,
      ciphersuite,
      attachment,
    );
    const { attachment: filled } = encryptMediaFile(file, fileKey, attachment);

    expect(filled.url).toBe("https://example.com/blob");
    expect(filled.dimensions).toBe("800x600");
    expect(filled.blurhash).toBe("LEHV6nWB2yk8pyo0adR*.7kCMdnj");
    expect(filled.alt).toBe("A test image");
  });

  it("throws when ciphertext is tampered (AEAD failure)", async () => {
    const { clientState, ciphersuite } = await makeClientState();
    const file = randomBytes(64);
    const attachment = makeAttachment(file);

    const fileKey = await deriveMip04FileKey(
      clientState,
      ciphersuite,
      attachment,
    );
    const { encrypted, attachment: filled } = encryptMediaFile(
      file,
      fileKey,
      attachment,
    );
    encrypted[0] ^= 0xff;
    expect(() => decryptMediaFile(encrypted, fileKey, filled)).toThrow();
  });

  it("throws when filename is tampered (AAD mismatch)", async () => {
    const { clientState, ciphersuite } = await makeClientState();
    const file = randomBytes(64);
    const attachment = makeAttachment(file, "image/jpeg", "real.jpg");

    const fileKey = await deriveMip04FileKey(
      clientState,
      ciphersuite,
      attachment,
    );
    const { encrypted, attachment: filled } = encryptMediaFile(
      file,
      fileKey,
      attachment,
    );
    expect(() =>
      decryptMediaFile(encrypted, fileKey, {
        ...filled,
        filename: "tampered.jpg",
      }),
    ).toThrow();
  });

  it("throws when MIME type is tampered (AAD mismatch)", async () => {
    const { clientState, ciphersuite } = await makeClientState();
    const file = randomBytes(64);
    const attachment = makeAttachment(file, "image/jpeg", "file.jpg");

    const fileKey = await deriveMip04FileKey(
      clientState,
      ciphersuite,
      attachment,
    );
    const { encrypted, attachment: filled } = encryptMediaFile(
      file,
      fileKey,
      attachment,
    );
    expect(() =>
      decryptMediaFile(encrypted, fileKey, { ...filled, type: "image/png" }),
    ).toThrow();
  });

  it("throws when wrong key is used", async () => {
    const { clientState, ciphersuite } = await makeClientState();
    const file = randomBytes(64);
    const attachment = makeAttachment(file);

    const fileKey = await deriveMip04FileKey(
      clientState,
      ciphersuite,
      attachment,
    );
    const { encrypted, attachment: filled } = encryptMediaFile(
      file,
      fileKey,
      attachment,
    );
    expect(() =>
      decryptMediaFile(encrypted, randomBytes(32), filled),
    ).toThrow();
  });

  it("throws when nonce is missing from attachment", () => {
    const attachment: Mip04MediaAttachment = {
      ...makeAttachment(randomBytes(32)),
      nonce: "",
    };
    expect(() =>
      decryptMediaFile(randomBytes(48), randomBytes(32), attachment),
    ).toThrow("nonce");
  });

  it("throws when fileHash in attachment is wrong (AAD mismatch)", async () => {
    const { clientState, ciphersuite } = await makeClientState();
    const file = randomBytes(64);
    const attachment = makeAttachment(file);

    const fileKey = await deriveMip04FileKey(
      clientState,
      ciphersuite,
      attachment,
    );
    const { encrypted, attachment: filled } = encryptMediaFile(
      file,
      fileKey,
      attachment,
    );
    expect(() =>
      decryptMediaFile(encrypted, fileKey, {
        ...filled,
        sha256: bytesToHex(sha256(randomBytes(64))),
      }),
    ).toThrow();
  });
});
