export async function register(username) {
  const res = await fetch("http://localhost:9999/register/begin", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include", // This is crucial for sending cookies
    body: JSON.stringify({ username }),
  });
  const options = await res.json();

  // The options are now nested under publicKey
  const publicKeyOptions = options.publicKey;
  publicKeyOptions.user.id = base64urlToBuffer(publicKeyOptions.user.id);
  publicKeyOptions.challenge = base64urlToBuffer(publicKeyOptions.challenge);

  const cred = await navigator.credentials.create({
    publicKey: publicKeyOptions,
  });

  await fetch("http://localhost:9999/register/complete", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include", // This is crucial for sending cookies
    body: JSON.stringify({
      clientDataJSON: bufferToBase64url(cred.response.clientDataJSON),
      attestationObject: bufferToBase64url(cred.response.attestationObject),
    }),
  });
}

export async function login(username) {
  const res = await fetch("http://localhost:9999/login/begin", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include", // This is crucial for sending cookies
    body: JSON.stringify({ username }),
  });
  const options = await res.json();

  // The options are now nested under publicKey
  const publicKeyOptions = options.publicKey;
  publicKeyOptions.challenge = base64urlToBuffer(publicKeyOptions.challenge);
  if (publicKeyOptions.allowCredentials) {
    publicKeyOptions.allowCredentials = publicKeyOptions.allowCredentials.map(
      (cred) => ({
        ...cred,
        id: base64urlToBuffer(cred.id),
      })
    );
  }

  const assertion = await navigator.credentials.get({
    publicKey: publicKeyOptions,
  });

  await fetch("http://localhost:9999/login/complete", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include", // This is crucial for sending cookies
    body: JSON.stringify({
      credentialId: bufferToBase64url(assertion.rawId),
      clientDataJSON: bufferToBase64url(assertion.response.clientDataJSON),
      authenticatorData: bufferToBase64url(
        assertion.response.authenticatorData
      ),
      signature: bufferToBase64url(assertion.response.signature),
    }),
  });
}

function base64urlToBuffer(base64url) {
  if (!base64url) return new Uint8Array(0);

  const base64 = base64url
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(Math.ceil(base64url.length / 4) * 4, "=");

  const binary = atob(base64);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

function bufferToBase64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}
