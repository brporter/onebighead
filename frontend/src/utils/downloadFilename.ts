/** Reads the filename without including other Content-Disposition parameters. */
export function downloadFilename(disposition: string | null, fallback: string): string {
  if (!disposition) return fallback;

  const encoded = disposition.match(/(?:^|;)\s*filename\*\s*=\s*UTF-8'[^']*'([^;]*)/i);
  if (encoded) {
    try {
      const filename = decodeURIComponent(encoded[1].trim());
      if (filename) return filename;
    } catch {
      // A malformed encoded name must not prevent downloading the archive.
    }
  }

  const plain = disposition.match(/(?:^|;)\s*filename\s*=\s*(?:"((?:\\.|[^"\\])*)"|([^;]*))/i);
  if (!plain) return fallback;
  const filename = plain[1] !== undefined ? plain[1].replace(/\\(.)/g, '$1') : plain[2].trim();
  return filename || fallback;
}
