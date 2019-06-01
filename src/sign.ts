export type SignOptions = {
  keyPair: CryptoKeyPair,
  request: RequestInit;
  keyId: string;
  algorithm: "rsa-sha256" | "rsa-sha384" | "rsa-sha512";
  url?: string; // Must be included if `request-line` or `request-target` is wanted
  version?: string; // Must be included if `request-line` is wanted,
  include: string[]; // Headers & options to include
};

const utf8TextDecoder = new TextDecoder("utf8");

export function getRequestLine(options: SignOptions): string {
  if (!options.url) {
    throw new Error("url is required when using request-line");
  }
  if (!options.version) {
    throw new Error("version is required when using request-line");
  }
  const url = new URL(options.url);
  return `${options.request.method.toLowerCase()} ${url.pathname} ${options.version}`;
}

export function getRequestTarget(options: SignOptions): string {
  if (!options.url) {
    throw new Error("url is required when using (request-target)");
  }
  const url = new URL(options.url);
  return `(request-target): ${options.request.method.toLowerCase()} ${url.pathname}`;
}

export function getSigningString(options: SignOptions) {
  const mapping: { [key: string]: (options: SignOptions) => string } = {
    "request-line": getRequestLine,
    "(request-target)": getRequestTarget
  };
  const headers = new Headers(options.request.headers);
  return options.include
    .map(key => mapping[key] || ((options: SignOptions) => {
      if (!options.request.headers) {
        throw new Error(`No headers provided when header "${key}" was requested to be signed`);
      }
      if (!headers.has(key)) {
        throw new Error(`Header "${key}" was requested to be signed but not present`);
      }
      return `${key}: ${headers.get(key)}`;
    }))
    .map(fn => fn(options))
    .join("\n");
}

export async function sign(options: SignOptions) {
  const signingString = getSigningString(options);
  const signature = await crypto.subtle.sign(
    options.keyPair.publicKey.algorithm.name,
    options.keyPair.privateKey,
    new TextEncoder().encode(signingString)
  );
  const utf8 = utf8TextDecoder.decode(signature);
  const base64 = btoa(utf8);
  return `Signature keyId=${options.keyId},algorithm="${options.algorithm}",headers="${options.include.join(" ")}",signature="${base64}"`;
}
