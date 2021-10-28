import "./styles.css";
import { Encode, Decode } from "./hex";
import KeyManager from "./key-manager";

function bootstrap() {
  if (!window.crypto || !window.crypto.subtle) {
    console.error(
      "Your browser does not support the Web Cryptography API! This page will not work."
    );
    return;
  }

  const messageOutput = document.getElementById("message-output");

  const passwordInput = <HTMLInputElement>document.getElementById("password");
  const generateUserkeyBtn = <HTMLButtonElement>(
    document.getElementById("generate-userkey")
  );
  const saltOutput = <HTMLInputElement>document.getElementById("salt");

  const publicKeyField = <HTMLTextAreaElement>(
    document.getElementById("public-key")
  );
  const privateKeyField = <HTMLTextAreaElement>(
    document.getElementById("private-key")
  );

  const resetBtn = <HTMLButtonElement>document.getElementById("reset");
  const generateKeyPairBtn = <HTMLButtonElement>(
    document.getElementById("generate-keypair")
  );
  const exportKeyPairBtn = <HTMLButtonElement>(
    document.getElementById("export-keypair")
  );
  const importKeyPairBtn = <HTMLButtonElement>(
    document.getElementById("import-keypair")
  );

  function showMessage(message, state?) {
    messageOutput.textContent = message;
    if (state) {
      console.log(message);
      console.log(state);
    }
  }

  function on(el, event, callback) {
    el.addEventListener(event, (ev) => {
      ev.preventDefault();
      if (event === "click") {
        showMessage("Working...");
      }

      callback();
    });
  }

  // Value for checking that everything worked okay:
  interface CheckSecret {
    value: string;
    encrypted: ArrayBuffer;
  }

  const secret: CheckSecret = { value: null, encrypted: null };

  // Create a new KeyManager Instance:
  const keyManager = new KeyManager(window.crypto);
  let salt = keyManager.generateSalt();

  function setMessage(message) {
    showMessage(message, keyManager.getInternalState());
  }

  function reset() {
    salt = keyManager.generateSalt();

    secret.value = null;
    secret.encrypted = null;

    passwordInput.value = "";
    saltOutput.value = Encode(salt);

    publicKeyField.value = "";
    privateKeyField.value = "";

    generateKeyPairBtn.setAttribute("disabled", "true");
    exportKeyPairBtn.setAttribute("disabled", "true");
    importKeyPairBtn.setAttribute("disabled", "true");

    setMessage("Ready!");
  }

  on(saltOutput, "input", (ev) => {
    if (
      saltOutput.value.length === 32 &&
      /[a-f0-9]{32}/.test(saltOutput.value)
    ) {
      salt = new Uint8Array(Decode(saltOutput.value));
      setMessage("Loaded salt!");
    } else {
      setMessage("Invalid salt: must be 32 hexadecimal characters");
    }
  });

  on(publicKeyField, "input", (ev) => {
    if (publicKeyField.value && privateKeyField.value) {
      importKeyPairBtn.removeAttribute("disabled");
    } else {
      importKeyPairBtn.setAttribute("disabled", "true");
    }
  });

  on(privateKeyField, "input", (ev) => {
    if (publicKeyField.value && privateKeyField.value) {
      importKeyPairBtn.removeAttribute("disabled");
    } else {
      importKeyPairBtn.setAttribute("disabled", "true");
    }
  });

  reset();

  function readPassword() {
    if (passwordInput.value.length < 8) {
      setMessage("Password must be greater than 8 characters long");
      return;
    }

    return passwordInput.value;
  }

  on(resetBtn, "click", () => {
    reset();
  });

  on(generateUserkeyBtn, "click", async () => {
    const password = readPassword();

    if (!password) return;

    try {
      await keyManager.deriveUserKey("test@example.org", password, salt);

      setMessage("Generated user key");

      generateKeyPairBtn.removeAttribute("disabled");
    } catch (err) {
      setMessage("Error: " + err.message);
    }
  });

  on(generateKeyPairBtn, "click", async () => {
    setMessage("Generating keypair...");

    try {
      await keyManager.generateKeyPair();

      setMessage("Generated keypair");
      exportKeyPairBtn.removeAttribute("disabled");
    } catch (err) {
      console.error("Generate", err.message);
    }
  });

  on(exportKeyPairBtn, "click", async (ev) => {
    if (!keyManager.hasKeyPair()) {
      setMessage("Missing keypair for session, click 'Generate Keypair'.");
      return;
    }

    if (!keyManager.hasUserKey()) {
      setMessage(
        "Missing userKey for session, enter a password above, and click 'Generate User Keys'."
      );
      return;
    }

    secret.value = new Date().toString();
    secret.encrypted = await keyManager.encrypt(secret.value);

    console.log("Secret: ", secret);

    try {
      const privateKey = await keyManager.exportKey();
      const publicKey = await keyManager.exportPublicKey();

      publicKeyField.value = Encode(publicKey);
      privateKeyField.value = Encode(privateKey);

      importKeyPairBtn.removeAttribute("disabled");

      setMessage("Exported!");
    } catch (err) {
      setMessage("Export Error:" + err.message);
    }
  });

  on(importKeyPairBtn, "click", async () => {
    if (!keyManager.hasUserKey()) {
      setMessage("Missing userKey for session");
      return;
    }

    const publicKey = Decode(publicKeyField.value);
    const privateKey = Decode(privateKeyField.value);

    try {
      await keyManager.importPublicKey(publicKey);
      await keyManager.importKey(privateKey);

      if (keyManager.hasKeyPair()) {
        if (secret.encrypted && secret.value) {
          const decryptedSecret = await keyManager.decrypt(secret.encrypted);

          console.log("Secret Value: ", decryptedSecret);
          console.log(
            "Secret Value Matches:",
            decryptedSecret === secret.value
          );

          if (!decryptedSecret) {
            setMessage("Error: Could not decrypt secret");
          } else if (decryptedSecret !== secret.value) {
            setMessage("Error: secrets do not match, something went wrong");
          }
        }

        setMessage("Imported!");
      } else {
        setMessage("Error: Could not import keys");
      }
    } catch (err) {
      console.log(err);
      setMessage("Error: " + (err.message || err.name));
    }
  });

  console.clear();
}

try {
  bootstrap();
} catch (err) {
  console.error(err);
}
