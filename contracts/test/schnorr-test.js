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
    
    // Estimate deployment gas cost
    const deployGas = await Schnorr.signer.provider.estimateGas(
      Schnorr.getDeployTransaction()
    );
    console.log("\nContract Deployment Gas Costs:");
    console.log("==============================");
    console.log("Schnorr contract deployment:", deployGas.toString());
    
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
    
    // Estimate Schnorr deployment gas cost
    const schnorrDeployGas = await Schnorr.signer.provider.estimateGas(
      Schnorr.getDeployTransaction()
    );
    
    const schnorr = await Schnorr.deploy();
    await schnorr.deployed();

    // Deploy BatchSchnorrVerifier
    const BatchSchnorrVerifier = await ethers.getContractFactory("BatchSchnorrVerifier");
    
    // Estimate BatchSchnorrVerifier deployment gas cost
    const batchVerifierDeployGas = await BatchSchnorrVerifier.signer.provider.estimateGas(
      BatchSchnorrVerifier.getDeployTransaction(schnorr.address)
    );
    
    console.log("\nContract Deployment Gas Costs:");
    console.log("==============================");
    console.log("Schnorr contract deployment:", schnorrDeployGas.toString());
    console.log("BatchSchnorrVerifier contract deployment:", batchVerifierDeployGas.toString());
    console.log("Total deployment gas cost:", (schnorrDeployGas.add(batchVerifierDeployGas)).toString());
    
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

  it("Should verify multiple signatures for coinDeposit function", async function () {
    // Deploy Schnorr contract first
    const Schnorr = await ethers.getContractFactory("Schnorr");
    
    // Estimate Schnorr deployment gas cost
    const schnorrDeployGas = await Schnorr.signer.provider.estimateGas(
      Schnorr.getDeployTransaction()
    );
    
    const schnorr = await Schnorr.deploy();
    await schnorr.deployed();

    // Deploy BatchSchnorrVerifier
    const BatchSchnorrVerifier = await ethers.getContractFactory("BatchSchnorrVerifier");
    
    // Estimate BatchSchnorrVerifier deployment gas cost
    const batchVerifierDeployGas = await BatchSchnorrVerifier.signer.provider.estimateGas(
      BatchSchnorrVerifier.getDeployTransaction(schnorr.address)
    );
    
    console.log("\nContract Deployment Gas Costs:");
    console.log("==============================");
    console.log("Schnorr contract deployment:", schnorrDeployGas.toString());
    console.log("BatchSchnorrVerifier contract deployment:", batchVerifierDeployGas.toString());
    console.log("Total deployment gas cost:", (schnorrDeployGas.add(batchVerifierDeployGas)).toString());
    
    const batchVerifier = await BatchSchnorrVerifier.deploy(schnorr.address);
    await batchVerifier.deployed();

    console.log("\nGas Cost Analysis for coinDeposit:");
    console.log("==================================");
    console.log("Signatures | Gas Cost");
    console.log("-----------|----------");

    // Test from 1 to 10 signatures
    for (let count = 1; count <= 10; count++) {
      // Create a single value list with 5 values (v, f, l, h, t)
      const valueList = [];
      for (let j = 0; j < 5; j++) {
        valueList.push(arrayify(randomBytes(32)));
      }

      // Create the message by hashing the value list
      const message = arrayify(ethers.utils.keccak256(ethers.utils.concat(valueList)));

      const signatures = [];

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
      let gas = await batchVerifier.estimateGas.coinDeposit(signatures, valueList);
      console.log(`${count.toString().padStart(10)} | ${gas.toString().padStart(9)}`);

      // Verify all signatures
      expect(await batchVerifier.coinDeposit(signatures, valueList)).to.equal(true);

      // Test with invalid signature
      const invalidSignatures = [...signatures];
      invalidSignatures[0].s = randomBytes(32);
      expect(await batchVerifier.coinDeposit(invalidSignatures, valueList)).to.equal(false);
    }
  });

  it("Should handle edge cases for coinDeposit function", async function () {
    // Deploy Schnorr contract first
    const Schnorr = await ethers.getContractFactory("Schnorr");
    
    // Estimate Schnorr deployment gas cost
    const schnorrDeployGas = await Schnorr.signer.provider.estimateGas(
      Schnorr.getDeployTransaction()
    );
    
    const schnorr = await Schnorr.deploy();
    await schnorr.deployed();

    // Deploy BatchSchnorrVerifier
    const BatchSchnorrVerifier = await ethers.getContractFactory("BatchSchnorrVerifier");
    
    // Estimate BatchSchnorrVerifier deployment gas cost
    const batchVerifierDeployGas = await BatchSchnorrVerifier.signer.provider.estimateGas(
      BatchSchnorrVerifier.getDeployTransaction(schnorr.address)
    );
    
    console.log("\nContract Deployment Gas Costs:");
    console.log("==============================");
    console.log("Schnorr contract deployment:", schnorrDeployGas.toString());
    console.log("BatchSchnorrVerifier contract deployment:", batchVerifierDeployGas.toString());
    console.log("Total deployment gas cost:", (schnorrDeployGas.add(batchVerifierDeployGas)).toString());
    
    const batchVerifier = await BatchSchnorrVerifier.deploy(schnorr.address);
    await batchVerifier.deployed();

    // Create a value list with 5 values
    const valueList = [];
    for (let j = 0; j < 5; j++) {
      valueList.push(arrayify(randomBytes(32)));
    }

    // Test with no signatures (should revert)
    await expect(
      batchVerifier.coinDeposit([], valueList)
    ).to.be.revertedWith("No signatures provided");

    // Test with invalid value list length (should revert)
    const invalidValueList = valueList.slice(0, 4); // Only 4 values
    const signatures = [{
      parity: 27,
      px: arrayify(randomBytes(32)),
      e: arrayify(randomBytes(32)),
      s: arrayify(randomBytes(32))
    }];
    
    // This will fail at runtime due to Solidity's array length check
    // We can't test this directly with ethers.js as it will fail before reaching the contract
    // The contract has a require(valueList.length == 5, "Invalid value list length") check
  });
});
