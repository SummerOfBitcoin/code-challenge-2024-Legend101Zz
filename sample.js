const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { validateTransaction } = require("./blockFunctions");

// Function to calculate the hash of a buffer
function hash256(buffer) {
  const hash1 = crypto.createHash("sha256").update(buffer).digest();
  return crypto.createHash("sha256").update(hash1).digest();
}

// Function to calculate the merkle root
function calculateMerkleRoot(txids) {
  if (txids.length === 0) return Buffer.alloc(32);

  const leaves = txids.map((txid) => Buffer.from(txid, "hex").reverse());
  let level = leaves;

  while (level.length > 1) {
    const nextLevel = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = i + 1 === level.length ? left : level[i + 1];
      const data = Buffer.concat([left, right]);
      nextLevel.push(hash256(data));
    }
    level = nextLevel;
  }

  return level[0].reverse();
}

// Function to construct the coinbase transaction
function constructCoinbaseTx(blockHeight, witnessCommitment) {
  const input = Buffer.from([
    0xba,
    0xda,
    0x85, // Push the block height (random value for this example)
    0x23,
    0x76,
    0x98,
    0x76,
    0x54,
    0x34,
    0x12,
    0x79,
    0x69,
    0x16, // Arbitrary data
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
    0xff,
  ]);

  const output1 = Buffer.from([
    0x51,
    0x51, // OP_DATA_25 (block reward)
    0x0b,
    0x2f,
    0x89,
    0x68,
    0x67,
    0x01,
    0x00,
    0x00,
    0x00,
    0x00,
    0x19,
    0x76,
    0xa9,
    0x14,
    0x1d,
    0xb7,
    0x8e,
    0x25,
    0x71,
    0x6e,
    0x59,
    0x37,
    0xc3,
    0x45,
    0x51,
    0x21,
    0x6d,
    0xa6,
    0x33,
    0x76,
    0x88,
    0xac,
  ]);

  const output2 = Buffer.from([
    0x6a,
    0x24, // OP_RETURN OP_PUSHDATA(36)
    ...Buffer.from(witnessCommitment, "hex"),
  ]);

  const tx = Buffer.concat([
    Buffer.from("01000000", "hex"), // Version
    Buffer.from("01", "hex"), // Input count
    input, // Input script
    Buffer.from("ffffffff", "hex"), // Sequence
    Buffer.from("02", "hex"), // Output count
    output1, // Output 1 (block reward)
    output2, // Output 2 (witness commitment)
    Buffer.from("00000000", "hex"), // Lock time
  ]);

  return tx.toString("hex");
}

// Function to mine the block
function mineBlock(blockHeader, target) {
  const targetBuffer = Buffer.from(target, "hex");
  let nonce = 0;
  let headerBuffer;

  do {
    headerBuffer = Buffer.concat([
      Buffer.from(blockHeader.slice(0, 76), "hex"),
      Buffer.from(nonce.toString(16).padStart(8, "0"), "hex"),
    ]);
    nonce++;
  } while (hash256(headerBuffer).compare(targetBuffer) >= 0);

  return headerBuffer.toString("hex");
}

// Main function
async function main() {
  const mempoolDir = path.join(__dirname, "mempool");
  const validTransactions = [];

  // Read and validate transactions from the mempool folder
  const files = await fs.promises.readdir(mempoolDir);
  for (const file of files) {
    const txData = await fs.promises.readFile(
      path.join(mempoolDir, file),
      "utf8"
    );
    const tx = JSON.parse(txData);

    // Validate the transaction
    if (validateTransaction(tx)) {
      validTransactions.push(tx.txid);
    }
  }

  // Construct the coinbase transaction
  const witnessCommitment =
    "0000000000000000000000000000000000000000000000000000000000000000"; // Dummy value
  const coinbaseTx = constructCoinbaseTx(1, witnessCommitment);

  // Calculate the merkle root
  const txids = [coinbaseTx, ...validTransactions];
  const merkleRoot = calculateMerkleRoot(txids).toString("hex");

  // Construct the block header
  const blockHeader = [
    "01000000", // Version
    "0000000000000000000000000000000000000000000000000000000000000000", // Previous block hash
    merkleRoot,
    "29ab5f49", // Time (little-endian)
    "1f00ffff", // Bits
    "00000000", // Nonce (placeholder)
  ].join("");

  // Mine the block
  const target =
    "0000ffff00000000000000000000000000000000000000000000000000000000";
  const minedBlockHeader = mineBlock(blockHeader, target);

  // Write the output.txt file
  const outputPath = path.join(__dirname, "output.txt");
  const outputData = [minedBlockHeader, coinbaseTx, ...validTransactions].join(
    "\n"
  );

  await fs.promises.writeFile(outputPath, outputData);
  console.log("Block mined and output.txt written successfully!");
}

main().catch((err) => console.error(err));
