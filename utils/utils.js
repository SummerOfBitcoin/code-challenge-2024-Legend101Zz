const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const secp256k1 = require("secp256k1");

const MEMPOOL_DIR = "mempool";
const OUTPUT_FILE = "output.txt";
const DIFFICULTY_TARGET =
  "0000ffff00000000000000000000000000000000000000000000000000000000";

/**
 * Serialize transaction based on the input address type.
 * @param {Object} transaction - The transaction object.
 * @returns {Buffer} The serialized transaction.
 */
function serializeTransaction(transaction) {
  const buffer = Buffer.alloc(0);
  const serializeInput = (input) => {
    const prevoutBuffer = Buffer.from(input.prevout.scriptpubkey, "hex");
    const scriptSigBuffer = Buffer.from(input.scriptsig, "hex");
    const witnessBuffer = Buffer.concat(
      input.witness.map((wit) => Buffer.from(wit, "hex"))
    );
    return Buffer.concat([prevoutBuffer, scriptSigBuffer, witnessBuffer]);
  };

  const serializeOutput = (output) => {
    const scriptPubKeyBuffer = Buffer.from(output.scriptpubkey, "hex");
    const valueBuffer = Buffer.alloc(8);
    valueBuffer.writeBigUInt64LE(BigInt(output.value));
    return Buffer.concat([scriptPubKeyBuffer, valueBuffer]);
  };

  buffer.writeUInt32LE(transaction.version);
  buffer.writeUInt8(transaction.vin.length);
  transaction.vin.forEach((input) => buffer.writeBuffer(serializeInput(input)));
  buffer.writeUInt8(transaction.vout.length);
  transaction.vout.forEach((output) =>
    buffer.writeBuffer(serializeOutput(output))
  );
  buffer.writeUInt32LE(transaction.locktime);

  return buffer;
}

/**
 * Validate a transaction based on its input address type.
 * @param {Object} transaction - The transaction object.
 * @returns {boolean} True if the transaction is valid, false otherwise.
 */
function validateTransaction(transaction) {
  const validateP2PKH = (input) => {
    const scriptSig = Buffer.from(input.scriptsig, "hex");
    const scriptPubKey = Buffer.from(input.prevout.scriptpubkey, "hex");
    const tx = serializeTransaction(transaction);
    const hashType = scriptSig.readUInt8(scriptSig.length - 1);
    const signatureLength = scriptSig.readUInt8(0);
    const signature = scriptSig.slice(1, signatureLength + 1);
    const publicKey = scriptSig.slice(signatureLength + 1);

    const hash = crypto.createHash("sha256").update(tx).digest();
    const hashBuff = Buffer.alloc(32);
    hashBuff.writeBigUInt64LE(BigInt(`0x${hash.toString("hex")}`));

    return secp256k1.ecdsaVerify(hashBuff, signature, publicKey);
  };

  const validateP2WPKH = (input) => {
    const witness = input.witness;
    const signature = Buffer.from(witness[0], "hex");
    const publicKey = Buffer.from(witness[1], "hex");
    const scriptPubKey = Buffer.from(input.prevout.scriptpubkey, "hex");
    const tx = serializeTransaction(transaction);
    const hashType = signature.readUInt8(signature.length - 1);
    const signatureLength = signature.length - 1;
    const sigBuff = signature.slice(0, signatureLength);

    const hash = crypto.createHash("sha256").update(tx).digest();
    const hashBuff = Buffer.alloc(32);
    hashBuff.writeBigUInt64LE(BigInt(`0x${hash.toString("hex")}`));

    return secp256k1.ecdsaVerify(hashBuff, sigBuff, publicKey);
  };

  const validateP2TR = (input) => {
    const witness = input.witness;
    const scriptPubKey = Buffer.from(input.prevout.scriptpubkey, "hex");
    const tx = serializeTransaction(transaction);

    const internalKey = witness[0];
    const merkleRoot = witness[1];
    const controlBlock = witness[2];

    // Validate internal key, merkle root, and control block
    // ...

    const hashBuff = crypto.createHash("sha256").update(tx).digest();
    const hashBigInt = BigInt(`0x${hashBuff.toString("hex")}`);

    // Verify the signature using the internal key, merkle root, and control block
    // ...

    return true; // Return true if the signature is valid, false otherwise
  };

  const validateScriptPubKey = (input) => {
    const scriptPubKey = Buffer.from(input.prevout.scriptpubkey_asm, "hex");
    const ops = [];

    for (let i = 0; i < scriptPubKey.length; i++) {
      const opCode = scriptPubKey[i];

      if (opCode >= 0x01 && opCode <= 0x4b) {
        // Push data operation
        const dataLength = opCode;
        const data = scriptPubKey.slice(i + 1, i + 1 + dataLength);
        ops.push({ op: "push", data: data.toString("hex") });
        i += dataLength;
      } else if (opCode >= 0x51 && opCode <= 0x60) {
        // Push number operation
        const num = opCode - 0x50;
        ops.push({ op: "push", data: num.toString(16).padStart(2, "0") });
      } else {
        // Other operations
        ops.push({ op: "code", code: opCode });
      }
    }

    // Validate the script operations
    // ...

    return true; // Return true if the script is valid, false otherwise
  };

  const validateScriptSig = (input) => {
    const scriptSig = input.scriptsig_asm
      ? Buffer.from(input.scriptsig_asm, "hex")
      : Buffer.alloc(0);
    const ops = [];

    for (let i = 0; i < scriptSig.length; i++) {
      const opCode = scriptSig[i];

      if (opCode >= 0x01 && opCode <= 0x4b) {
        // Push data operation
        const dataLength = opCode;
        const data = scriptSig.slice(i + 1, i + 1 + dataLength);
        ops.push({ op: "push", data: data.toString("hex") });
        i += dataLength;
      } else if (opCode >= 0x51 && opCode <= 0x60) {
        // Push number operation
        const num = opCode - 0x50;
        ops.push({ op: "push", data: num.toString(16).padStart(2, "0") });
      } else {
        // Other operations
        ops.push({ op: "code", code: opCode });
      }
    }

    // Validate the script operations
    // ...

    return true; // Return true if the script is valid, false otherwise
  };

  for (const input of transaction.vin) {
    const scriptPubKeyType = input.prevout.scriptpubkey_type;
    if (scriptPubKeyType === "p2pkh") {
      if (!validateP2PKH(input)) {
        return false;
      }
      if (!validateScriptPubKey(input)) {
        return false;
      }
      if (!validateScriptSig(input)) {
        return false;
      }
    } else if (scriptPubKeyType === "v0_p2wpkh") {
      if (!validateP2WPKH(input)) {
        return false;
      }
      if (!validateScriptPubKey(input)) {
        return false;
      }
    } else if (scriptPubKeyType === "v1_p2tr") {
      if (!validateP2TR(input)) {
        return false;
      }
      if (!validateScriptPubKey(input)) {
        return false;
      }
    } else {
      console.warn(`Unsupported script type: ${scriptPubKeyType}`);
      return false;
    }
  }

  return true;
}


module.exports = { validateTransaction ,serializeTransaction,};