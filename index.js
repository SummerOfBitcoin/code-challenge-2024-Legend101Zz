const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const secp256k1 = require("secp256k1");

const MEMPOOL_DIR = "mempool";
const OUTPUT_FILE = "output.txt";
const DIFFICULTY_TARGET =
  "0000ffff00000000000000000000000000000000000000000000000000000000";
const MAX_BLOCK_SIZE = 1_000_000; // 1 MB in bytes

// Step 1: Read Transactions from Mempool
const readTransactionsFromMempool = () => {
  const transactions = fs
    .readdirSync(MEMPOOL_DIR)
    .map((file) =>
      JSON.parse(fs.readFileSync(path.join(MEMPOOL_DIR, file), "utf8"))
    );
  return transactions;
};

// Step 2: Validate Transactions and Filter Valid Ones

/**
 * Serialize transaction based on the input address type.
 * @param {Object} transaction - The transaction object.
 * @returns {Buffer} The serialized transaction.
 */
function serializeTransaction(transaction) {
  // console.log("transaction", transaction.vin[0].prevout, transaction);
  let buffer = Buffer.alloc(0);
  const serializeInput = (input) => {
    const prevoutBuffer = Buffer.from(input.prevout.scriptpubkey, "hex");
    const scriptSigBuffer = input.scriptsig
      ? Buffer.from(input.scriptsig, "hex")
      : Buffer.alloc(0);
    const witnessBuffer = input.witness
      ? Buffer.concat(input.witness.map((wit) => Buffer.from(wit, "hex")))
      : Buffer.alloc(0);
    return Buffer.concat([prevoutBuffer, scriptSigBuffer, witnessBuffer]);
  };

  const serializeOutput = (output) => {
    const scriptPubKeyBuffer = Buffer.from(output.scriptpubkey, "hex");
    let valueBuffer = Buffer.alloc(8);
    valueBuffer.writeBigUInt64LE(BigInt(output.value));
    return Buffer.concat([scriptPubKeyBuffer, valueBuffer]);
  };
  buffer = Buffer.concat([
    buffer,
    Buffer.from([
      transaction.version >>> 24,
      (transaction.version >>> 16) & 0xff,
      (transaction.version >>> 8) & 0xff,
      transaction.version & 0xff,
    ]),
    Buffer.from([transaction.vin.length]),
  ]);

  for (const input of transaction.vin) {
    buffer = Buffer.concat([buffer, serializeInput(input)]);
  }

  buffer = Buffer.concat([buffer, Buffer.from([transaction.vout.length])]);

  for (const output of transaction.vout) {
    buffer = Buffer.concat([buffer, serializeOutput(output)]);
  }

  buffer = Buffer.concat([
    buffer,
    Buffer.from([
      transaction.locktime >>> 24,
      (transaction.locktime >>> 16) & 0xff,
      (transaction.locktime >>> 8) & 0xff,
      transaction.locktime & 0xff,
    ]),
  ]);

  return buffer;
}

/**
 * Validate a transaction based on its input address type.
 * @param {Object} transaction - The transaction object.
 * @returns {boolean} True if the transaction is valid, false otherwise.
 */
function validateTransaction(transaction) {
  const validateP2PKH = (input) => {
    // console.log("in validateP2PKH", input);
    const scriptSig = Buffer.from(input.scriptsig, "hex");
    const scriptPubKey = Buffer.from(input.prevout.scriptpubkey, "hex");
    const tx = serializeTransaction(transaction);
    const hash = crypto.createHash("sha256").update(tx).digest();

    // Extracting signature and public key
    const signatureLength = scriptSig.readUInt8(0);
    const signatureEndIndex = 1 + signatureLength;
    const signature = scriptSig.slice(1, signatureEndIndex);
    // Extracting public key length
    const publicKeyLength = scriptSig.readUInt8(signatureEndIndex);
    const publicKeyEndIndex = signatureEndIndex + 1 + publicKeyLength;

    // Extracting public key
    const publicKey = scriptSig.slice(signatureEndIndex + 1, publicKeyEndIndex);
    // console.log("in validateP2PKH public key", publicKeyLength, publicKey);
    // Ensure publicKey is in the correct format (33 or 65 bytes)
    if (publicKey.length !== 33 && publicKey.length !== 65) {
      throw new Error("Invalid public key length");
    }

    // Prepare signature as two 32-byte values
    const rValue = signature.slice(0, 32);
    const sValue = signature.slice(32);
    const signatureArray = new Uint8Array(64);
    rValue.copy(signatureArray, 0);
    sValue.copy(signatureArray, 32);

    // Verify the signature
    return secp256k1.ecdsaVerify(signatureArray, hash, publicKey);
  };

  const validateP2WPKH = (input) => {
    const witness = input.witness;
    const signatureBuffer = Buffer.from(witness[0], "hex");
    const publicKey = Buffer.from(witness[1], "hex");
    const scriptPubKey = Buffer.from(input.prevout.scriptpubkey, "hex");
    const tx = serializeTransaction(transaction);

    const txHash = crypto.createHash("sha256").update(tx).digest();
    const hash = crypto.createHash("sha256").update(txHash).digest();

    const signatureLength = signatureBuffer.length - 1;
    const rValue = signatureBuffer.slice(0, 32);
    const sValue = signatureBuffer.slice(32, 64);

    const signature = new Uint8Array(64);
    rValue.copy(signature, 0);
    sValue.copy(signature, 32);

    return secp256k1.ecdsaVerify(signature, hash, publicKey);
  };

  const validateP2SH = (input) => {
    const redeemScript = Buffer.from(
      input.inner_redeemscript_asm.split(" ").slice(1).join(""),
      "hex"
    );
    const scriptSig = Buffer.from(
      input.scriptsig_asm.split(" ").slice(1).join(""),
      "hex"
    );
    const tx = serializeTransaction(transaction);
    const hash = crypto.createHash("sha256").update(tx).digest();

    // Execute the redeem script
    const redeemScriptResult = executeScript(redeemScript, scriptSig, hash);

    // Validate the redeem script result
    if (!redeemScriptResult) {
      console.error("P2SH validation failed: invalid redeem script execution");
      return false;
    }

    return true;
  };

  const validateV0P2WSH = (input) => {
    const witness = input.witness.map((item) => Buffer.from(item, "hex"));
    const witnessScript = Buffer.from(
      input.prevout.scriptpubkey_asm.split(" ").slice(1).join(""),
      "hex"
    );
    const tx = serializeTransaction(transaction);
    const hash = crypto.createHash("sha256").update(tx).digest();

    // Execute the witness script
    const witnessScriptResult = executeScript(witnessScript, witness, hash);

    // Validate the witness script result
    if (!witnessScriptResult) {
      console.error(
        "v0 P2WSH validation failed: invalid witness script execution"
      );
      return false;
    }

    return true;
  };

  const validateP2TR = (input) => {
    //console.log("in validateP2TR", input);
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
        const dataLength = opCode;
        const data = scriptSig.slice(i + 1, i + 1 + dataLength);
        ops.push({ op: "push", data: data.toString("hex") });
        i += dataLength;
      } else if (opCode >= 0x51 && opCode <= 0x60) {
        const num = opCode - 0x50;
        ops.push({ op: "push", data: num.toString(16).padStart(2, "0") });
      } else {
        ops.push({ op: "code", code: opCode });
      }
    }

    // Validate the script operations
    // ...

    return true;
  };

  const executeScript = (script, ...stackItems) => {
    const stack = [];
    let scriptIndex = 0;

    const opcodes = {
      OP_0: 0x00,
      OP_PUSHDATA1: 0x4c,
      OP_PUSHDATA2: 0x4d,
      OP_PUSHDATA4: 0x4e,
      OP_1NEGATE: 0x4f,
      OP_1: 0x51,
      OP_16: 0x60,
      OP_CHECKSIG: 0xac,
      OP_CHECKMULTISIG: 0xae,
      // Add more opcodes as needed
    };

    const popStackItem = () => {
      if (stack.length === 0) return undefined;
      return stack.pop();
    };

    const pushStackItem = (item) => {
      stack.push(item);
    };

    while (scriptIndex < script.length) {
      const opcode = script[scriptIndex];

      if (opcode in opcodes) {
        switch (opcode) {
          case opcodes.OP_0:
            pushStackItem(Buffer.alloc(0));
            break;
          case opcodes.OP_PUSHDATA1:
            const dataLength = script[scriptIndex + 1];
            const data = script.slice(
              scriptIndex + 2,
              scriptIndex + 2 + dataLength
            );
            pushStackItem(data);
            scriptIndex += dataLength;
            break;
          case opcodes.OP_PUSHDATA2:
            // Handle OP_PUSHDATA2
            break;
          case opcodes.OP_PUSHDATA4:
            // Handle OP_PUSHDATA4
            break;
          case opcodes.OP_1NEGATE:
          case opcodes.OP_1:
          case opcodes.OP_16:
            const num = opcode - 0x50;
            pushStackItem(Buffer.from([num]));
            break;
          case opcodes.OP_CHECKSIG:
            // Handle OP_CHECKSIG
            break;
          case opcodes.OP_CHECKMULTISIG:
            // Handle OP_CHECKMULTISIG
            break;
          // Add cases for other opcodes
        }
      } else {
        // Handle non-opcode bytes
      }

      scriptIndex++;
    }

    // Return true if script execution is successful, false otherwise
    return true;
  };

  for (const input of transaction.vin) {
    const scriptPubKeyType = input.prevout.scriptpubkey_type;
    switch (scriptPubKeyType) {
      case "p2pkh":
        if (input.scriptsig) {
          if (!validateP2PKH(input)) {
            return false;
          }
        } else {
          if (!validateScriptSig(input)) {
            return false;
          }
        }
        break;
      case "v0_p2wpkh":
        if (input.witness && input.witness.length > 0) {
          if (!validateP2WPKH(input)) {
            return false;
          }
        } else {
          if (!validateScriptSig(input)) {
            return false;
          }
        }
        break;
      case "v1_p2tr":
        if (!validateP2TR(input)) {
          return false;
        }
        break;
      case "p2sh":
        if (!validateP2SH(input)) {
          return false;
        }
        break;
      case "v0_p2wsh":
        if (!validateV0P2WSH(input)) {
          return false;
        }
        break;
      default:
        console.warn(`Unsupported script type: ${scriptPubKeyType}`);
        return false;
    }
    if (!validateScriptPubKey(input)) {
      return false;
    }
  }

  return true;
}

const getValidTransactions = (transactions) => {
  return transactions.filter(validateTransaction);
};

// Step 3: Construct the Block
const constructBlock = (validTransactions) => {
  const coinbaseTransaction = {
    version: 1,
    locktime: 0,
    vin: [
      {
        txid: "0000000000000000000000000000000000000000000000000000000000000000",
        vout: 4294967295,
        prevout: {
          scriptpubkey: "0014cbbfcc021f4dbd0697f7e02eb1949a70be183375",
          scriptpubkey_asm:
            "OP_0 OP_PUSHBYTES_20 cbbfcc021f4dbd0697f7e02eb1949a70be183375",
          scriptpubkey_type: "v0_p2wpkh",
          scriptpubkey_address: "bc1qewlucqslfk7sd9lhuqhtr9y6wzlpsvm46wyugs",
          value: 0,
        },
        scriptsig: "",
        scriptsig_asm: "",
        witness: [
          "3044022079c55b9397f12c131e2f4618acae8c27c575c8e6b8547a46e706b4523280176802200f8f0fdefa78f62be8403952dea982642f52b9fded1b4e882f481815e1377b3701",
          "0367a853d263f0b45548fcbdef9e63ee30ded60a3f3ac86462d4d3f49b22298e60",
        ],
        is_coinbase: true,
        sequence: 4294967295,
      },
    ],
    vout: [
      {
        scriptpubkey: "a91420756d2dd9f0cc05fe200794251642ff9e76008587",
        scriptpubkey_asm:
          "OP_HASH160 OP_PUSHBYTES_20 20756d2dd9f0cc05fe200794251642ff9e760085 OP_EQUAL",
        scriptpubkey_type: "p2sh",
        scriptpubkey_address: "34eeDckhVvGkbnTzGx6qbz2AkmyV9syc8R",
        value: 50000000,
      },
    ],
  };

  // Sort valid transactions based on fees
  const sortedTransactions = validTransactions.sort((a, b) => {
    const aFee =
      a.vout.reduce((acc, output) => acc + output.value, 0) -
      a.vin.reduce((acc, input) => acc + input.prevout.value, 0);
    const bFee =
      b.vout.reduce((acc, output) => acc + output.value, 0) -
      b.vin.reduce((acc, input) => acc + input.prevout.value, 0);
    return bFee - aFee;
  });

  // Construct the block with the sorted transactions
  let blockSize = serializeTransaction(coinbaseTransaction).length;
  const blockTransactions = [coinbaseTransaction];

  for (const tx of sortedTransactions) {
    const txSize = serializeTransaction(tx).length;
    if (blockSize + txSize > MAX_BLOCK_SIZE) {
      break;
    }
    blockTransactions.push(tx);
    blockSize += txSize;
  }

  return blockTransactions;
};

// Step 4: Mine the Block
const mineBlock = (blockTransactions) => {
  let nonce = 0;
  let blockHeader = "";
  let interval = 1000; // Adjust this interval based on performance
  const merkleRoot = calculateMerkleRoot(blockTransactions);
  // Generate a random previous block hash
  const previousBlockHash = crypto
    .createHash("sha256")
    .update(Math.random().toString())
    .digest("hex");

  while (true) {
    const timestamp = Math.floor(Date.now() / 1000);
    const version = 4;

    // Construct the block header
    const blockData = `${version
      .toString(16)
      .padStart(8, "0")}${previousBlockHash}${merkleRoot}${timestamp
      .toString(16)
      .padStart(8, "0")}${DIFFICULTY_TARGET}${nonce
      .toString(16)
      .padStart(8, "0")}`;

    // Calculate the hash of the block header
    const hash = crypto.createHash("sha256").update(blockData).digest("hex");
    // console.log("mining baby", hash);
    if (hash < DIFFICULTY_TARGET) {
      // If the hash meets the difficulty target, break the loop
      blockHeader = blockData;
      break;
    }

    // Increment nonce and continue mining
    nonce += interval;

    // Check if we've overshot the target
    const nextBlockData = `${version
      .toString(16)
      .padStart(8, "0")}${previousBlockHash}${merkleRoot}${timestamp
      .toString(16)
      .padStart(8, "0")}${DIFFICULTY_TARGET}${nonce
      .toString(16)
      .padStart(8, "0")}`;
    const nextHash = crypto
      .createHash("sha256")
      .update(nextBlockData)
      .digest("hex");

    if (nextHash > DIFFICULTY_TARGET) {
      // If we overshot, reduce the interval
      interval = Math.floor(interval / 2);
      if (interval === 0) {
        interval = 1;
      }
    }
  }

  return { blockHeader, blockTransactions };
};

const calculateMerkleRoot = (transactions) => {
  if (transactions.length === 0) {
    return "0000000000000000000000000000000000000000000000000000000000000000";
  }

  let hashes = transactions.map((tx) =>
    crypto.createHash("sha256").update(serializeTransaction(tx)).digest()
  );

  while (hashes.length > 1) {
    const newHashes = [];
    for (let i = 0; i < hashes.length; i += 2) {
      const hash1 = hashes[i];
      const hash2 = i + 1 < hashes.length ? hashes[i + 1] : hash1;
      const combinedHash = crypto
        .createHash("sha256")
        .update(Buffer.concat([hash1, Buffer.alloc(32), hash2]))
        .digest();
      newHashes.push(combinedHash);
    }
    hashes = newHashes;
  }

  return Buffer.from(hashes[0]).toString("hex");
};

// Main function
const main = () => {
  const transactions = readTransactionsFromMempool();
  const validTransactions = getValidTransactions(transactions);

  const blockTransactions = constructBlock(validTransactions);
  const { blockHeader, blockTransactions: minedTransactions } =
    mineBlock(blockTransactions);

  const serializedCoinbaseTransaction = serializeTransaction(
    minedTransactions[0]
  ).toString("hex");
  const txids = minedTransactions.map((tx) =>
    crypto.createHash("sha256").update(serializeTransaction(tx)).digest("hex")
  );

  const output = `${blockHeader}\n${serializedCoinbaseTransaction}\n${txids.join(
    "\n"
  )}`;
  fs.writeFileSync(OUTPUT_FILE, output);
  console.log(
    "length",
    blockHeader,
    transactions.length,
    validTransactions.length
  );
};

main();
