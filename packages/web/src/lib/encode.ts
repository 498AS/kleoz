export function encodeSessionKey(sessionKey: string): string {
  // Contract: sessionKey in path must be URL-encoded.
  return encodeURIComponent(sessionKey);
}

