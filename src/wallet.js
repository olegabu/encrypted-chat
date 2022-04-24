const bip39 = require('bip39');
const HDKey = require('hdkey');
const EC = require('elliptic').ec;
const ec = new EC('secp256k1');
const CryptoJS = require("crypto-js");

module.exports = class Wallet {
  constructor(mnemonic) {
    if(!mnemonic) {
      mnemonic = bip39.generateMnemonic();
    } else if (!bip39.validateMnemonic(mnemonic)){
      throw new Error('invalid mnemonic: ' + mnemonic);
    }

    this.mnemonic = mnemonic;
    this.masterKey = HDKey.fromMasterSeed(bip39.mnemonicToSeedSync(mnemonic));
  }

  getSharedSecret(otherPublicKey) {
    const otherHDPublicKey = HDKey.fromExtendedKey(otherPublicKey);
    const otherECPublicKey = ec.keyFromPublic(otherHDPublicKey.publicKey);

    const chatHDKey = this.getChatKey();
    const myECPrivateKey = ec.keyFromPrivate(chatHDKey.privateKey);

    const sharedSecret = otherECPublicKey.getPublic().mul(myECPrivateKey.getPrivate());

    return sharedSecret.getX().toString(16);
  }

  encrypt(msg, otherPublicKey) {
    const sharedSecret = this.getSharedSecret(otherPublicKey);
    const ciphertext = CryptoJS.AES.encrypt(msg, sharedSecret).toString();
    return ciphertext;
  }

  decrypt(ciphertext, otherPublicKey) {
    const sharedSecret = this.getSharedSecret(otherPublicKey);
    const bytes = CryptoJS.AES.decrypt(ciphertext, sharedSecret);
    return bytes.toString(CryptoJS.enc.Utf8);
  }

  getChatKey() {
    return this.masterKey.derive('m/0/1');
  }

  getTransactionPrivateKey() {
    return this.masterKey.derive('m/0/2');
  }

  getChatPublicKey() {
    return this.getChatKey().publicExtendedKey;
  }
}