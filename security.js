export const nanoid = (t = 21) =>
  crypto
    .getRandomValues(new Uint8Array(t))
    .reduce(
      (t, e) =>
        (t +=
          (e &= 63) < 36
            ? e.toString(36)
            : e < 62
            ? (e - 26).toString(36).toUpperCase()
            : e > 62
            ? '-'
            : '_'),
      ''
    );

export const generateKeyPair = async () => {
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: 'ECDH',
      namedCurve: 'P-256',
    },
    true,
    ['deriveKey', 'deriveBits']
  );

  const publicKeyJwk = await window.crypto.subtle.exportKey(
    'jwk',
    keyPair.publicKey
  );

  const privateKeyJwk = await window.crypto.subtle.exportKey(
    'jwk',
    keyPair.privateKey
  );

  return { publicKeyJwk, privateKeyJwk };
};

export const deriveKey = async (publicKeyJwk, privateKeyJwk) => {
  const publicKey = await window.crypto.subtle.importKey(
    'jwk',
    publicKeyJwk,
    {
      name: 'ECDH',
      namedCurve: 'P-256',
    },
    true,
    []
  );

  const privateKey = await window.crypto.subtle.importKey(
    'jwk',
    privateKeyJwk,
    {
      name: 'ECDH',
      namedCurve: 'P-256',
    },
    true,
    ['deriveKey', 'deriveBits']
  );

  return await window.crypto.subtle.deriveKey(
    { name: 'ECDH', public: publicKey },
    privateKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
};

export const encryptMessage = async (text, derivedKey) => {
  const encodedText = new TextEncoder().encode(text);
  const initVector = nanoid();

  const encryptedData = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: new TextEncoder().encode(initVector) },
    derivedKey,
    encodedText
  );

  const uintArray = new Uint8Array(encryptedData);

  const msgString = String.fromCharCode.apply(null, uintArray);

  const message = {
    data: msgString,
    iv: initVector,
  };

  const base64Data = btoa(JSON.stringify(message));

  return base64Data;
};

export const decryptMessage = async (base64Data, derivedKey) => {
  try {
    const decodedData = atob(base64Data);
    const message = JSON.parse(decodedData);

    const text = message.data;

    const uintArray = new Uint8Array(
      [...text].map((char) => char.charCodeAt(0))
    );

    const algorithm = {
      name: 'AES-GCM',
      iv: new TextEncoder().encode(message.iv),
    };

    const decryptedData = await window.crypto.subtle.decrypt(
      algorithm,
      derivedKey,
      uintArray
    );

    return new TextDecoder().decode(decryptedData);
  } catch (e) {
    return `error decrypting message: ${e}`;
  }
};
