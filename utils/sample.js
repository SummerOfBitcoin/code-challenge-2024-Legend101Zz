// const crypto = require("crypto");
// const fs = require("fs");
// const path = require("path");
// const { validateTransaction } = require("./blockFunctions");

// // Function to calculate the hash of a buffer
// function hash256(buffer) {
//   const hash1 = crypto.createHash("sha256").update(buffer).digest();
//   return crypto.createHash("sha256").update(hash1).digest();
// }

// // Function to calculate the merkle root
// function calculateMerkleRoot(txids) {
//   if (txids.length === 0) return Buffer.alloc(32);

//   const leaves = txids.map((txid) => Buffer.from(txid, "hex").reverse());
//   let level = leaves;

//   while (level.length > 1) {
//     const nextLevel = [];
//     for (let i = 0; i < level.length; i += 2) {
//       const left = level[i];
//       const right = i + 1 === level.length ? left : level[i + 1];
//       const data = Buffer.concat([left, right]);
//       nextLevel.push(hash256(data));
//     }
//     level = nextLevel;
//   }

//   return level[0].reverse();
// }

// // Function to construct the coinbase transaction
// function constructCoinbaseTx(blockHeight, witnessCommitment) {
//   const input = Buffer.from([
//     0xba,
//     0xda,
//     0x85, // Push the block height (random value for this example)
//     0x23,
//     0x76,
//     0x98,
//     0x76,
//     0x54,
//     0x34,
//     0x12,
//     0x79,
//     0x69,
//     0x16, // Arbitrary data
//     0xff,
//     0xff,
//     0xff,
//     0xff,
//     0xff,
//     0xff,
//     0xff,
//     0xff,
//     0xff,
//     0xff,
//     0xff,
//     0xff,
//     0xff,
//     0xff,
//     0xff,
//     0xff,
//     0xff,
//     0xff,
//     0xff,
//     0xff,
//     0xff,
//     0xff,
//     0xff,
//     0xff,
//     0xff,
//     0xff,
//     0xff,
//     0xff,
//     0xff,
//     0xff,
//     0xff,
//     0xff,
//   ]);

//   const output1 = Buffer.from([
//     0x51,
//     0x51, // OP_DATA_25 (block reward)
//     0x0b,
//     0x2f,
//     0x89,
//     0x68,
//     0x67,
//     0x01,
//     0x00,
//     0x00,
//     0x00,
//     0x00,
//     0x19,
//     0x76,
//     0xa9,
//     0x14,
//     0x1d,
//     0xb7,
//     0x8e,
//     0x25,
//     0x71,
//     0x6e,
//     0x59,
//     0x37,
//     0xc3,
//     0x45,
//     0x51,
//     0x21,
//     0x6d,
//     0xa6,
//     0x33,
//     0x76,
//     0x88,
//     0xac,
//   ]);

//   const output2 = Buffer.from([
//     0x6a,
//     0x24, // OP_RETURN OP_PUSHDATA(36)
//     ...Buffer.from(witnessCommitment, "hex"),
//   ]);

//   const tx = Buffer.concat([
//     Buffer.from("01000000", "hex"), // Version
//     Buffer.from("01", "hex"), // Input count
//     input, // Input script
//     Buffer.from("ffffffff", "hex"), // Sequence
//     Buffer.from("02", "hex"), // Output count
//     output1, // Output 1 (block reward)
//     output2, // Output 2 (witness commitment)
//     Buffer.from("00000000", "hex"), // Lock time
//   ]);

//   return tx.toString("hex");
// }

// // Function to mine the block
// function mineBlock(blockHeader, target) {
//   const targetBuffer = Buffer.from(target, "hex");
//   let nonce = 0;
//   let headerBuffer;

//   do {
//     headerBuffer = Buffer.concat([
//       Buffer.from(blockHeader.slice(0, 76), "hex"),
//       Buffer.from(nonce.toString(16).padStart(8, "0"), "hex"),
//     ]);
//     nonce++;
//   } while (hash256(headerBuffer).compare(targetBuffer) >= 0);

//   return headerBuffer.toString("hex");
// }

// // Main function
// async function main() {
//   const mempoolDir = path.join(__dirname, "mempool");
//   const validTransactions = [];

//   // Read and validate transactions from the mempool folder
//   const files = await fs.promises.readdir(mempoolDir);
//   for (const file of files) {
//     const txData = await fs.promises.readFile(
//       path.join(mempoolDir, file),
//       "utf8"
//     );
//     const tx = JSON.parse(txData);

//     // Validate the transaction
//     if (validateTransaction(tx)) {
//       validTransactions.push(tx.txid);
//     }
//   }

//   // Construct the coinbase transaction
//   const witnessCommitment =
//     "0000000000000000000000000000000000000000000000000000000000000000"; // Dummy value
//   const coinbaseTx = constructCoinbaseTx(1, witnessCommitment);

//   // Calculate the merkle root
//   const txids = [coinbaseTx, ...validTransactions];
//   const merkleRoot = calculateMerkleRoot(txids).toString("hex");

//   // Construct the block header
//   const blockHeader = [
//     "01000000", // Version
//     "0000000000000000000000000000000000000000000000000000000000000000", // Previous block hash
//     merkleRoot,
//     "29ab5f49", // Time (little-endian)
//     "1f00ffff", // Bits
//     "00000000", // Nonce (placeholder)
//   ].join("");

//   // Mine the block
//   const target =
//     "0000ffff00000000000000000000000000000000000000000000000000000000";
//   const minedBlockHeader = mineBlock(blockHeader, target);

//   // Write the output.txt file
//   const outputPath = path.join(__dirname, "output.txt");
//   const outputData = [minedBlockHeader, coinbaseTx, ...validTransactions].join(
//     "\n"
//   );

//   await fs.promises.writeFile(outputPath, outputData);
//   console.log("Block mined and output.txt written successfully!");
// }

// main().catch((err) => console.error(err));
// const headerBuffer = Buffer.from(
//   "4bb0823783df8765661df66a93566e112a1c8ef57823d26b76fb7d50d9377f8d3a47586f78e825c24d70ad7136cfd3642254cc331d840aca68f81cf4a84002ef617143422380000ffff00000000000000000000000000000000000000000000000000000000157661",
//   "hex"
// );
// console.log(headerBuffer.length);
// if (headerBuffer.length !== 80) throw new Error("Invalid header length");
// console.log(headerBuffer);
const crypto = require("crypto");

const calculateMerkleRoot = (transactions) => {
  if (transactions.length === 0) {
    return "0000000000000000000000000000000000000000000000000000000000000000";
  }

  let hashes = transactions.map((tx) => Buffer.from(tx.txid, "hex").reverse());

  while (hashes.length > 1) {
    const newHashes = [];
    for (let i = 0; i < hashes.length; i += 2) {
      const hash1 = hashes[i];
      let hash2;
      if (i + 1 < hashes.length) {
        hash2 = hashes[i + 1];
      } else {
        // If there's an odd number of hashes, duplicate the last hash
        hash2 = hash1;
      }
      const combinedHash = crypto
        .createHash("sha256")
        .update(
          crypto
            .createHash("sha256")
            .update(Buffer.concat([hash1, hash2]))
            .digest()
        )
        .digest();
      newHashes.push(combinedHash);
    }
    hashes = newHashes;
  }

  return Buffer.from(hashes[0]).reverse().toString("hex");
};

// Test cases
const testMerkleRoot = (transactions, expectedMerkleRoot) => {
  const merkleRoot = calculateMerkleRoot(transactions);
  console.log(`Transactions: ${transactions.length}`);
  console.log(`Expected Merkle Root: ${expectedMerkleRoot}`);
  console.log(`Calculated Merkle Root: ${merkleRoot}`);
  console.log(`Merkle Root Matched: ${merkleRoot === expectedMerkleRoot}\n`);
};

// Test Case 1: Even number of transactions
const evenTransactions = [
  { txid: "8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87" },
  { txid: "fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4" },
  { txid: "6359f0868171b1d194cbee1af2f16ea598ae8fad666d9b012c8ed2b79a236ec4" },
  { txid: "e9a66845e05d5abc0ad04ec80f774a7e585c6e8db975962d069a522137b80c1d" },
];
const expectedEvenMerkleRoot =
  "f3e94742aca4b5ef85488dc37c06c3282295ffec960994b2c0d5ac2a25a95766";
testMerkleRoot(evenTransactions, expectedEvenMerkleRoot);

// Test Case 2: Odd number of transactions
const oddTransactions = [
  { txid: "8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87" },
  { txid: "fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4" },
  { txid: "6359f0868171b1d194cbee1af2f16ea598ae8fad666d9b012c8ed2b79a236ec4" },
];
const expectedOddMerkleRoot =
  "8b30c5ba100f6f2e5ad1e2a742e5020491240f8eb514fe97c713c31718ad7ecd";
testMerkleRoot(oddTransactions, expectedOddMerkleRoot);

const headerBuffer = Buffer.from(
  "0400000000000000000000000000000000000000000000000000000000000000000000001ad8b2e36cb607b79f58878561b1b66107049b3190bdcb1252b78722743787eeb7303166ffff001f39080100",
  "hex"
);
if (headerBuffer.length !== 80) throw new Error("Invalid header length");
const difficulty = Buffer.from(
  "0000ffff00000000000000000000000000000000000000000000000000000000",
  "hex"
);
// double SHA256 and reverse
const h1 = crypto.createHash("sha256").update(headerBuffer).digest();
const h2 = crypto.createHash("sha256").update(h1).digest();
const hash = h2.reverse();
console.log("hash", hash);
if (difficulty.compare(hash) < 0)
  throw new Error("Block does not meet target difficulty");
