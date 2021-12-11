/* eslint-disable */
// TODO: Remove previous line and work through linting issues at next edit

'use strict';

var should = require('chai').should();
var expect = require('chai').expect;

var bitcore = require('..');
var Point = bitcore.crypto.Point;
var BN = bitcore.crypto.BN;
var PublicKey = bitcore.PublicKey;
var PrivateKey = bitcore.PrivateKey;
var Address = bitcore.Address;
var Networks = bitcore.Networks;
const LoadBLS = require('@liutianv1/bls-signatures');
const { randomBytes } = require("crypto");

const Payload = bitcore.Transaction.Payload;
const SubTxRegisterPayload = Payload.SubTxRegisterPayload;
const RegisteredTransactionTypes = Payload.constants.registeredTransactionTypes;
const Script = bitcore.Script;
const Transaction = bitcore.Transaction;
const proRegTxFixture = require('./payload/proregtxpayload');
const ProRegTxPayload = Payload.ProRegTxPayload;
const crypto = require('crypto');

describe('Generate Addresses', function() {
    it('can produce valid private and public address', function () {
        const privateKey = new bitcore.PrivateKey("XCfeyaBUUTnkQHyHYVHDjjPRh8EUURKW6okjfPYiXox5VjjneZ2T");
        const publicKey = new bitcore.Address(privateKey.publicKey).toString();
        publicKey.should.equal("PKQUBVv5Sy8bB6Wwng2F9a1XGLYvJYhqvK");
    })
});

describe('BLS Keypair', () => {
    it('should generate BLS Keypair', async function () {
        const BLS = await LoadBLS();
        const seed = Uint8Array.from(crypto.randomBytes(32))
        const sk = BLS.AugSchemeMPL.key_gen(seed);
        const pk = sk.get_g1();
       // const publicKey = BLS.PublicKey.fromBytes(privateKey);
        console.log(sk);
        console.log(pk);
        console.log(sk.serialize());
        console.log(pk.serialize());
        console.log(Buffer.from(sk.serialize()).toString("hex"));
        console.log(Buffer.from(pk.serialize()).toString("hex"));
       // console.log(publicKey);
        //publicKey.should.equal("a7e75af9dd4d868a41ad2f5a5b021d653e31084261724fb40ae2f1b1c31c778d3b9464502d599cf6720723ec5c68b59d");

    })
});

const fromAddress = 'PLyAz4WAE2QShRnQs4iRrFyZx69EEy6BBE';
const privateKey = "XFGKGyKRmLPV6NLTQwVny5x82ysMn5ZKDBjx1hZvpUyPxDmEgfC9";
const simpleUtxoWith1PAC = {
  address: fromAddress,
  txId: 'a477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458',
  outputIndex: 1,
  script: Script.buildPublicKeyHashOut(fromAddress).toString(),
  satoshis: 1e8
};

describe('Special Transaction (protx)', () => {
    it('Should be possible to serialize and deserialize special transaction', function () {

        const transaction = Transaction()
            .from(simpleUtxoWith1PAC)
            .to(fromAddress, 10000)
            .change(fromAddress)
            .setType(RegisteredTransactionTypes.TRANSACTION_PROVIDER_REGISTER)
        
        const protx_register_payload_raw = {
            version: 3,
            type: 1,
            mode: 0,
            collateralHash: 'a188e6057605f2a2a86b211116829acad09ee91a20e796dd1e6fc0fbbae068e2',
            collateralIndex: 1,
            service: '195.141.0.143:7112',
            ownerAddress: 'PLyAz4WAE2QShRnQs4iRrFyZx69EEy6BBE',
            votingAddress: 'PCEoxGXMjLk6gDzPCwbeNj2ha5nUGzBZ9D',
            pubKeyOperator: '0e9e47c794c4b1b354d5d18208e0c9f7db160cc1150079361767de8c1808c103c8f3ecce2332f2923e90f45540db611a',
            operatorReward: 0,
            payoutAddress: 'PWBfmb5EkbkdUnXnuynV6CkUTqAig7fsMP',
            //inputsHash: '0b5e6a319019d8f1f4b17da96964df507e417f0a0ef8ca63eaa01e33e05510bc',
            inputsHash: ProRegTxPayload.calculateInputsHash(transaction)
        }
        const protx_register_payload = new ProRegTxPayload(protx_register_payload_raw)
        protx_register_payload.sign(privateKey);
        
        protx_register_payload.validate();
        
        console.log(protx_register_payload);
        
        transaction.setExtraPayload(protx_register_payload)
        transaction.sign(privateKey);

        const serialized = transaction.serialize();
        const deserialized = new Transaction(serialized);
        
       // console.log(transaction.toString());
        console.log("---", deserialized.toString())
        console.log(protx_register_payload.toString())
        expect(deserialized.type).to.be.equal(transaction.type);
    });
})

