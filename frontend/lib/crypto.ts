/**
 * Computes the SHA-256 hex digest of a File or Blob using the browser's WebCrypto API.
 * Returns lowercase hex string, or null if WebCrypto is unavailable or an error occurs.
 */
export async function computeFileSha256(file: File | Blob): Promise<string | null> {
  try {
    if (typeof window === "undefined" || typeof crypto === "undefined" || !crypto.subtle) {
      return null;
    }
    const buffer = await file.arrayBuffer();
    const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
  } catch (err) {
    console.warn("Client-side SHA-256 calculation failed:", err);
    return null;
  }
}
