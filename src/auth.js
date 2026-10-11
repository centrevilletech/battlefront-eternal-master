import { createHash, createHmac, createPublicKey, generateKeyPairSync, sign, verify, randomBytes } from 'node:crypto';
export const keyId = publicKey => createHash('sha256').update(publicKey).digest('hex');
export function identity() {
  const pair = generateKeyPairSync('ed25519');
  return { publicKey: pair.publicKey.export({format:'der',type:'spki'}).toString('base64'), privateKey:pair.privateKey.export({format:'pem',type:'pkcs8'}) };
}
export function signedHeaders(keys, method, path, body='', now=Date.now()) {
  const time=String(Math.floor(now/1000)), nonce=randomBytes(16).toString('hex');
  const message = `${method}\n${path}\n${time}\n${nonce}\n${createHash('sha256').update(body).digest('hex')}`;
  return {'x-bfe-key':keys.publicKey,'x-bfe-time':time,'x-bfe-nonce':nonce,'x-bfe-signature':sign(null,Buffer.from(message),keys.privateKey).toString('base64')};
}
export function authenticate(req, body, nonces, now=Date.now()) {
  const h=req.headers, key=h['x-bfe-key'], time=h['x-bfe-time'], nonce=h['x-bfe-nonce'], signature=h['x-bfe-signature'];
  if (typeof key!=='string'||key.length!==60||!/^\d{10}$/.test(time)||Math.abs(now/1000-Number(time))>60||! /^[a-f0-9]{32}$/.test(nonce)||typeof signature!=='string'||signature.length!==88) throw new Error('invalid authentication');
  const publicKey=createPublicKey({key:Buffer.from(key,'base64'),format:'der',type:'spki'});
  if (publicKey.asymmetricKeyType!=='ed25519'||publicKey.export({format:'der',type:'spki'}).toString('base64')!==key) throw new Error('invalid key');
  const message=`${req.method}\n${req.url}\n${time}\n${nonce}\n${createHash('sha256').update(body).digest('hex')}`;
  if (!verify(null,Buffer.from(message),publicKey,Buffer.from(signature,'base64'))) throw new Error('invalid signature');
  const id=keyId(key), replay=`${id}:${nonce}`;
  if (nonces.has(replay)) throw new Error('replayed request');
  if (nonces.size>=100000) throw new Error('authentication capacity reached');
  nonces.set(replay,now+125000); return {id,publicKey:key};
}
export function turnCredentials(secret, id, now=Date.now(), ttl=300) {
  const username=`${Math.floor(now/1000)+ttl}:${id}`;
  return {username,credential:createHmac('sha1',secret).update(username).digest('base64'),expires:Math.floor(now/1000)+ttl};
}
