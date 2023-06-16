import {
  generateKeyPair,
  deriveKey,
  encryptMessage,
  decryptMessage,
} from './security.js';

const { publicKeyJwk: pubKey1, privateKeyJwk: privKey1 } =
  await generateKeyPair();
const { publicKeyJwk: pubKey2, privateKeyJwk: privKey2 } =
  await generateKeyPair();

const dk1 = await deriveKey(pubKey2, privKey1);
const dk2 = await deriveKey(pubKey1, privKey2);

const encText = await encryptMessage('hello', dk1);
const decrpText = await decryptMessage(encText, dk2);
console.log(decrpText);
