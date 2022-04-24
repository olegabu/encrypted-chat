const expect = require('chai').expect;

const Wallet = require('../src/wallet');

const mnemonic1 = 'digital fatigue essay pretty number firm calm skirt exhibit seat able phrase';
const mnemonic2 = 'remove banner sunny matrix coral upper crop truck drive write view foot';
const invalidMnemonic = 'remove banner sunny matrix coral upper crop truck drive write view penis';
const chatPublicKey1 = 'xpub6Agr3jQk9FXFHMjBkAkWw9csexkxNePwjAyLQtWxYczHt5NkHfeFU1j54o6b5zSAeMfNPPVcU5oVyE5dMNghq2aonWoTdcH66GZcsPscWBv';

describe('Wallet', function () {
  describe('#constructor()', function () {
    it('should return new wallet from new mnemonic seed phrase', function () {
      const o = new Wallet();
      expect(o).to.be.a('object');
    });

    it('should recover a wallet from an existing mnemonic and have a known public key', function () {
      const o = new Wallet(mnemonic1);
      expect(o).to.be.a('object');
      const chatPublicKey = o.getChatPublicKey();
      expect(chatPublicKey).to.equal(chatPublicKey1);
    });

    it('should fail to create a wallet from an invalid mnemonic', function () {
      expect(function () {
        new Wallet(invalidMnemonic);
      }).to.throw(Error, /invalid mnemonic/);
    });
  });

  describe('#getSharedSecret()', function () {
    it('should return a secret shared by two parties via their public keys', function () {
      const w1 = new Wallet();
      const key1 = w1.getChatPublicKey();

      const w2 = new Wallet();
      const key2 = w2.getChatPublicKey();

      const secret1 = w1.getSharedSecret(key2);
      const secret2 = w2.getSharedSecret(key1);

      expect(secret1).to.equal(secret2);
    });
  });

  describe('#encrypt()', function () {
    it('should encrypt and decrypt by a secret shared by two parties', function () {
      const w1 = new Wallet();
      const key1 = w1.getChatPublicKey();

      const w2 = new Wallet();
      const key2 = w2.getChatPublicKey();

      const msg = 'hello привет Բարեւ';
      const ciphertext = w2.encrypt(msg, key1);
      const decrypted = w1.decrypt(ciphertext, key2);

      expect(msg).to.equal(decrypted);
    });
  });

});
