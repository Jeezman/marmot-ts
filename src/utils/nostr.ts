import { GiftWrapBlueprint } from "applesauce-common/blueprints/gift-wrap";
import { Rumor } from "applesauce-common/helpers/gift-wrap";
import { GiftWrapOptions } from "applesauce-common/operations/gift-wrap";
import { createEvent, EventSigner } from "applesauce-core/event-factory";
import { NostrEvent } from "applesauce-core/helpers/event";
import { PublishResponse } from "../client/nostr-interface.js";

/** Returns the value of a name / value tag */
export function getTagValue(
  event: NostrEvent,
  name: string,
): string | undefined {
  return event.tags.find((t) => t[0] === name)?.[1];
}

/**
 * Options for creating a gift wrap event for a welcome message.
 */
export interface CreateGiftWrapOptions {
  /** The unsigned welcome event (kind 444) to wrap */
  rumor: Rumor;
  /** The recipient's public key (hex string) */
  recipient: string;
  /** The signer for creating the gift wrap */
  signer: EventSigner;
  /** Optional gift wrap options */
  opts?: GiftWrapOptions;
}

/**
 * Creates a gift wrap event (kind 1059) for a welcome message.
 *
 * Uses applesauce-factory's GiftWrapBlueprint to create the gift wrap event
 * for the recipient, providing privacy and unlinkability (NIP-59).
 *
 * @param options - Configuration for creating the gift wrap
 * @returns A signed gift wrap event ready for publishing
 */
export async function createGiftWrap(
  options: CreateGiftWrapOptions,
): Promise<NostrEvent> {
  const { rumor, recipient, signer, opts } = options;

  // Use the GiftWrapBlueprint to create the gift wrap
  return await createEvent(
    { signer },
    GiftWrapBlueprint,
    recipient,
    rumor,
    opts,
  );
}

/** Returns the current Unix timestamp in seconds */
export function unixNow(): number {
  return Math.floor(Date.now() / 1000);
}

export const hasAck = (publishResult: Record<string, PublishResponse>) =>
  Object.values(publishResult).some((res) => res.ok);

/**
 * Publish an event with exponential-backoff retries.
 *
 * Retries up to `maxAttempts` times (default 5) with exponential backoff
 * starting at `baseDelayMs` (default 250ms). Only retries when at least one
 * relay error looks transient (auth / protected), otherwise fails fast.
 *
 * @returns The publish result once at least one relay acknowledges.
 * @throws {Error} after all attempts are exhausted.
 */
export async function publishWithRetries(
  publish: (
    relays: string[],
    event: NostrEvent,
  ) => Promise<Record<string, PublishResponse>>,
  relays: string[],
  event: NostrEvent,
  options?: { maxAttempts?: number; baseDelayMs?: number },
): Promise<Record<string, PublishResponse>> {
  const maxAttempts = options?.maxAttempts ?? 5;
  const baseDelayMs = options?.baseDelayMs ?? 250;

  let lastError: string | undefined;
  let lastResult: Record<string, PublishResponse> | undefined;

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    let result: Record<string, PublishResponse>;
    try {
      result = await publish(relays, event);
    } catch (err) {
      // Transport error (timeout, socket failure) — always retryable
      lastError = err instanceof Error ? err.message : String(err);
      lastResult = undefined;
      if (attempt < maxAttempts - 1) {
        const delay =
          baseDelayMs * Math.pow(2, attempt) * (0.5 + Math.random() * 0.5);
        await new Promise((resolve) => setTimeout(resolve, delay));
      }
      continue;
    }

    if (hasAck(result)) return result;

    lastResult = result;

    // Check if any error is retryable (auth / protected / NIP-42)
    const errors = Object.values(result)
      .filter((r) => !r.ok && r.message)
      .map((r) => r.message!.toLowerCase());

    const anyRetryable = errors.some(
      (e) => e.includes("auth") || e.includes("protected"),
    );
    if (!anyRetryable) break;

    // Exponential backoff — skip on final attempt to avoid pointless wait
    if (attempt < maxAttempts - 1) {
      const delay =
        baseDelayMs * Math.pow(2, attempt) * (0.5 + Math.random() * 0.5);
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }

  // Build a summary — prefer the most recent transport error over stale relay results
  const errorSummary =
    lastError ??
    (lastResult
      ? Object.values(lastResult)
          .filter((r) => !r.ok && r.message)
          .map((r) => r.message)
          .join("; ")
      : "no relay response");

  throw new Error(
    `Publish failed after ${maxAttempts} attempts: ${errorSummary}`,
  );
}
