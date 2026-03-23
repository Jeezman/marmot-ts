import {
  Capabilities,
  ciphersuites,
  defaultCapabilities as mlsDefaultCapabilities,
  defaultCredentialTypes,
  greaseValues,
} from "ts-mls";
import { ensureMarmotCapabilities } from "./capabilities.js";

/**
 * Default capabilities for Marmot key packages.
 *
 * According to MIP-01, key packages MUST signal support for the Marmot Group Data Extension
 * and ratchet_tree in their capabilities to pass validation when being added to groups.
 */
export function defaultCapabilities(): Capabilities {
  let capabilities = mlsDefaultCapabilities();
  const GREASE_VALUES = new Set<number>(greaseValues);

  // Ensure capabilities include the Marmot Group Data Extension
  capabilities = ensureMarmotCapabilities(capabilities);

  // Filter ciphersuites: keep the default one (MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)
  // and keep GREASE values (numeric IDs), but remove other MLS ciphersuites
  // In v2, ciphersuites is an object mapping names to numeric IDs
  const defaultCiphersuiteName = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519";

  capabilities.ciphersuites = Object.entries(ciphersuites)
    .filter(([name, id]) => {
      // Keep the default ciphersuite by name
      if (name === defaultCiphersuiteName) return true;
      // Keep canonical GREASE values published by ts-mls.
      if (GREASE_VALUES.has(id)) return true;
      return false;
    })
    .map(([, id]) => id) as Capabilities["ciphersuites"];

  // Only include "basic" credential type (remove "x509" since we don't support it)
  // In v2, credential types are numeric values (see defaultCredentialTypes)
  capabilities.credentials = capabilities.credentials.filter(
    (c) => c === defaultCredentialTypes.basic,
  );

  return capabilities;
}
