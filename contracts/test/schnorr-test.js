const { expect } = require("chai");
const { ethers } = require("hardhat");

const BigInteger = require('bigi')
const { randomBytes } = require('crypto')
const secp256k1 = require('secp256k1')

const arrayify = ethers.utils.arrayify;

function sign(m, x) {
  var publicKey = secp256k1.publicKeyCreate(x);

  // R = G * k
  var k = randomBytes(32);
  var R = secp256k1.publicKeyCreate(k);

  // e = h(address(R) || compressed pubkey || m)
  var e = challenge(R, m, publicKey);

  // xe = x * e
  var xe = secp256k1.privateKeyTweakMul(x, e);

  // s = k + xe
  var s = secp256k1.privateKeyTweakAdd(k, xe);
  return {R, s, e};
}

function challenge(R, m, publicKey) {
  // convert R to address
  // see https://github.com/ethereum/go-ethereum/blob/eb948962704397bb861fd4c0591b5056456edd4d/crypto/crypto.go#L275
  var R_uncomp = secp256k1.publicKeyConvert(R, false);
  var R_addr = arrayify(ethers.utils.keccak256(R_uncomp.slice(1, 65))).slice(12, 32);

  // e = keccak256(address(R) || compressed publicKey || m)
  var e = arrayify(ethers.utils.solidityKeccak256(
      ["address", "uint8", "bytes32", "bytes32"],
      [R_addr, publicKey[0] + 27 - 2, publicKey.slice(1, 33), m]));

  return e;
}

describe("Schnorr", function () {
  it("Should verify a signature", async function () {
    const Schnorr = await ethers.getContractFactory("Schnorr");
    const schnorr = await Schnorr.deploy();
    await schnorr.deployed();

    // generate privKey
    let privKey
    do {
      privKey = randomBytes(32)
    } while (!secp256k1.privateKeyVerify(privKey))

    var publicKey = secp256k1.publicKeyCreate(privKey);

    // message 
    var m = randomBytes(32);

    var sig = sign(m, privKey);

    let gas = await schnorr.estimateGas.verify(
      publicKey[0] - 2 + 27,
      publicKey.slice(1, 33),
      arrayify(m),
      sig.e,
      sig.s,
    )
    console.log("verify gas cost:", gas);

    expect(await schnorr.verify(
      publicKey[0] - 2 + 27,
      publicKey.slice(1, 33),
      arrayify(m),
      sig.e,
      sig.s,
    )).to.equal(true);
  });
});

describe("BatchSchnorrVerifier", function () {
  it("Should verify multiple signatures for the same message", async function () {
    // Deploy Schnorr contract first
    const Schnorr = await ethers.getContractFactory("Schnorr");
    const schnorr = await Schnorr.deploy();
    await schnorr.deployed();

    // Deploy BatchSchnorrVerifier
    const BatchSchnorrVerifier = await ethers.getContractFactory("BatchSchnorrVerifier");
    const batchVerifier = await BatchSchnorrVerifier.deploy(schnorr.address);
    await batchVerifier.deployed();

    console.log("\nGas Cost Analysis:");
    console.log("==================");
    console.log("Signatures/Value Lists | Gas Cost");
    console.log("---------------------|----------");

    // Test from 1 to 20 signatures and value lists
    for (let count = 1; count <= 20; count++) {
      const valueLists = [];
      const signatures = [];

      // Create lists of 5 values each
      for (let i = 0; i < count; i++) {
        const valueList = [];
        for (let j = 0; j < 5; j++) {
          valueList.push(arrayify(randomBytes(32)));
        }
        valueLists.push(valueList);
      }

      // Create the message by hashing all value lists together
      const message = arrayify(ethers.utils.keccak256(ethers.utils.concat(valueLists.flat())));

      // Generate signatures
      for (let i = 0; i < count; i++) {
        // Generate private key
        let privKey;
        do {
          privKey = randomBytes(32);
        } while (!secp256k1.privateKeyVerify(privKey));

        const publicKey = secp256k1.publicKeyCreate(privKey);
        
        // Sign the hashed message
        const sig = sign(message, privKey);

        signatures.push({
          parity: publicKey[0] - 2 + 27,
          px: publicKey.slice(1, 33),
          e: sig.e,
          s: sig.s
        });
      }

      // Estimate gas
      let gas = await batchVerifier.estimateGas.verifyBatch(signatures, valueLists);
      console.log(`${count.toString().padStart(19)} | ${gas.toString().padStart(9)}`);

      // Verify all signatures
      expect(await batchVerifier.verifyBatch(signatures, valueLists)).to.equal(true);

      // Test with invalid signature
      const invalidSignatures = [...signatures];
      invalidSignatures[0].s = randomBytes(32);
      expect(await batchVerifier.verifyBatch(invalidSignatures, valueLists)).to.equal(false);
    }
  });
});
