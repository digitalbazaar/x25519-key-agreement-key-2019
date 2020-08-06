// `scalarMult` takes secret key as param 1, public key as param 2
import nacl from 'tweetnacl';

export function deriveSecret({privateKey, remotePublicKey}) {
  return nacl.scalarMult(privateKey, remotePublicKey);
}

