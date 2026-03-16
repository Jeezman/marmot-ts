import { type CiphersuiteId } from "ts-mls";
import { getCiphersuiteNameFromId } from "../lib/ciphersuite";
import { GREASE_VALUES } from "../lib/grease";

interface CipherSuiteBadgeProps {
  cipherSuite: CiphersuiteId | number;
  className?: string;
}

/**
 * A badge component that displays a cipher suite ID with a tooltip showing its name
 */
export default function CipherSuiteBadge({
  cipherSuite,
  className = "",
}: CipherSuiteBadgeProps) {
  const isGrease = GREASE_VALUES.includes(cipherSuite);

  // Get the cipher suite name
  const cipherSuiteName = isGrease
    ? "GREASE"
    : (getCiphersuiteNameFromId(cipherSuite) ?? "Unknown");

  // Format the hex ID with 0x prefix
  const hexId = `0x${cipherSuite.toString(16).padStart(4, "0")}`;

  return (
    <span
      className={`badge badge-outline font-mono whitespace-pre ${className}`}
    >
      {cipherSuiteName} ({hexId})
    </span>
  );
}
