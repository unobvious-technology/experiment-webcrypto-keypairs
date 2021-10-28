interface Keypair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}

// interface ExportedKeyPair {
//   publicKey: Uint8Array;
//   privateKey: Uint8Array;
//   iv: Uint8Array;
// }

interface KeyParams {
  name: "RSA-OAEP";
  hash: "SHA-512" | "SHA-256";
  size: 1024 | 2048 | 4096;
}

interface UserKeyParams {
  name: "AES-GCM";
  length: 256;
}

interface KdfParams {
  name: "PBKDF2";
  iterations: number;
  hash: "SHA-512";
}

class KeyManager {
  // window.crypto.subtle API injected:
  private cryptoAPI: Crypto;
  private keyParams: KeyParams = {
    name: "RSA-OAEP",
    hash: "SHA-512",
    size: 4096
  };

  private kdfParams: KdfParams = {
    name: "PBKDF2",
    hash: "SHA-512",
    iterations: 10000
  };

  private userKeyParams: UserKeyParams = {
    name: "AES-GCM",
    length: 256
  };

  private textEncoder = new TextEncoder();
  private textDecoder = new TextDecoder("utf8");

  private keypair?: Keypair;
  private userKey?: CryptoKey;

  constructor(cryptoAPI: Crypto = window.crypto) {
    this.cryptoAPI = cryptoAPI;
  }

  public clear(): void {
    this.keypair = undefined;
    this.userKey = undefined;
  }

  public hasKeyPair(): boolean {
    return (
      this.keypair !== undefined &&
      !!this.keypair.publicKey &&
      !!this.keypair.privateKey
    );
  }

  public hasUserKey(): boolean {
    return !!this.userKey;
  }

  public getInternalState() {
    return {
      keypair: this.keypair,
      userKey: this.userKey
    };
  }

  public generateSalt(): Uint8Array {
    return this.cryptoAPI.getRandomValues(new Uint8Array(16));
  }

  private async importPassword(password: string): Promise<CryptoKey> {
    return this.cryptoAPI.subtle.importKey(
      "raw",
      this.textEncoder.encode(password),
      this.kdfParams.name,
      false,
      ["deriveKey", "deriveBits"]
    );
  }

  public async deriveUserKey(
    identity: string,
    password: string,
    salt: Uint8Array
  ): Promise<void> {
    const passwordKey = await this.importPassword(password);

    // TODO: derive salt from password & identity

    this.userKey = await this.cryptoAPI.subtle.deriveKey(
      {
        name: this.kdfParams.name,
        hash: this.kdfParams.hash,
        iterations: this.kdfParams.iterations,
        salt: salt
      },
      passwordKey,
      // AES-KW doesn't seem to work:
      // { name: "AES-KW", length: 256 },
      { name: this.userKeyParams.name, length: this.userKeyParams.length },
      false,
      ["wrapKey", "unwrapKey"]
    );
  }

  async generateKeyPair(): Promise<void> {
    this.keypair = await this.cryptoAPI.subtle.generateKey(
      {
        name: this.keyParams.name,
        hash: this.keyParams.hash,
        // Consider using a 4096-bit key for systems that require long-term security
        modulusLength: this.keyParams.size,
        // This is the standard exponent of 65537:
        // See: https://developer.mozilla.org/en-US/docs/Web/API/RsaHashedKeyGenParams#properties
        publicExponent: new Uint8Array([1, 0, 1])
      },
      // This keypair needs to be exportable
      true,
      // And we use it for encryption and decryption:
      ["encrypt", "decrypt"]
    );
  }

  async exportPublicKey(): Promise<ArrayBuffer> {
    if (!this.keypair || !this.keypair.publicKey) {
      throw new Error("Missing public key");
    }

    const exportedPublicKey = await this.cryptoAPI.subtle.exportKey(
      "spki", // spki is for public keys
      this.keypair.publicKey
    );

    return new Uint8Array(exportedPublicKey);
  }

  async importPublicKey(rawPublicKey: ArrayBuffer): Promise<void> {
    if (!this.keypair) {
      this.keypair = { publicKey: undefined, privateKey: undefined };
    }

    if (!this.keypair.publicKey) {
      this.keypair.publicKey = undefined;
    }

    this.keypair.publicKey = await this.cryptoAPI.subtle.importKey(
      "spki",
      rawPublicKey,
      {
        name: this.keyParams.name,
        hash: this.keyParams.hash
      },
      true,
      ["encrypt"]
    );
  }

  async exportKey(): Promise<ArrayBuffer> {
    if (!this.keypair || !this.keypair.privateKey) {
      throw new Error("Missing private key");
    }

    if (!this.userKey) {
      throw new Error("Missing user key");
    }

    const iv = this.cryptoAPI.getRandomValues(new Uint8Array(16));
    const wrapped = await this.cryptoAPI.subtle.wrapKey(
      "pkcs8", // pkcs8 is for private keys
      this.keypair.privateKey,
      this.userKey,
      // AES-KW doesn't seem to work:
      // { name: "AES-KW" }
      {
        name: this.userKeyParams.name,
        // @ts-ignore typescript is wrong with it's types
        iv
      }
    );

    // Pack the IV and Wrapped PrivateKey together:
    const result = new Uint8Array(iv.byteLength + wrapped.byteLength);
    result.set(iv, 0);
    result.set(new Uint8Array(wrapped), iv.byteLength);

    return result;
  }

  async importKey(rawKey: ArrayBuffer): Promise<void> {
    const iv = rawKey.slice(0, 16);
    const wrapped = rawKey.slice(16, rawKey.byteLength);

    if (rawKey.byteLength < 16) {
      throw new Error("Missing IV in rawKey");
    }

    if (!this.userKey) {
      throw new Error("Missing user key");
    }

    if (!this.keypair) {
      this.keypair = { publicKey: undefined, privateKey: undefined };
    }

    if (!this.keypair.privateKey) {
      this.keypair.privateKey = undefined;
    }

    this.keypair.privateKey = await this.cryptoAPI.subtle.unwrapKey(
      // import format
      "pkcs8",
      // ArrayBuffer representing key to unwrap
      wrapped,
      // CryptoKey representing key encryption key
      this.userKey,
      // algorithm identifier for key encryption key
      {
        name: "AES-GCM",
        // @ts-ignore
        iv
      },
      // algorithm identifier for key to unwrap
      { name: this.keyParams.name, hash: this.keyParams.hash },
      // extractability of key to unwrap
      true,
      // key usages for key to unwrap
      ["decrypt"]
    );
  }

  async encrypt(input: string): Promise<ArrayBuffer> {
    const crypted = await this.cryptoAPI.subtle.encrypt(
      this.keyParams.name,
      this.keypair.publicKey,
      this.textEncoder.encode(input)
    );

    return crypted;
  }

  async decrypt(input: ArrayBuffer): Promise<string> {
    return await this.cryptoAPI.subtle
      .decrypt(this.keyParams.name, this.keypair.privateKey, input)
      .then((decrypted) => this.textDecoder.decode(decrypted));
  }
}

export default KeyManager;
