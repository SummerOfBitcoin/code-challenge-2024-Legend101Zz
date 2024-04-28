const { createHash } = require("crypto");

/**
 * Perform double SHA256 hashing.
 * @param {string} input The input string to hash.
 * @returns {string} The double SHA256 hash of the input.
 */
const hash256 = (input) => {
  const h1 = createHash("sha256").update(Buffer.from(input, "hex")).digest();
  return createHash("sha256").update(h1).digest("hex");
};

/**
 * Generates the Merkle root hash from an array of transaction IDs (txids).
 * @param {string[]} txids Array of transaction IDs (txids).
 * @returns {string} The Merkle root hash.
 */
const generateMerkleRoot = (txids) => {
  if (txids.length === 0) return null;

  // Reverse the txids
  let level = txids.map((txid) =>
    Buffer.from(txid, "hex").reverse().toString("hex")
  );

  while (level.length > 1) {
    const nextLevel = [];

    for (let i = 0; i < level.length; i += 2) {
      let pairHash;
      if (i + 1 === level.length) {
        // In case of an odd number of elements, duplicate the last one
        pairHash = hash256(level[i] + level[i]);
      } else {
        pairHash = hash256(level[i] + level[i + 1]);
      }
      nextLevel.push(pairHash);
    }

    level = nextLevel;
  }

  return level[0];
};

/**
 * Represents the witness reserved value.
 */
const WITNESS_RESERVED_VALUE = Buffer.from(
  "0000000000000000000000000000000000000000000000000000000000000000",
  "hex"
);

/**
 * Validate a transaction.
 * @param {Object} transaction The transaction object to validate.
 * @returns {boolean} True if the transaction is valid, false otherwise.
 */
const validateTransaction = (transaction) => {
  // Validate transaction structure
  if (!transaction || typeof transaction !== "object") {
    return false;
  }

  // Validate version
  if (transaction.version !== 1 && transaction.version !== 2) {
    return false;
  }

  // Validate locktime
  if (transaction.locktime !== 0) {
    return false;
  }

  // Validate inputs
  if (
    !transaction.vin ||
    !Array.isArray(transaction.vin) ||
    transaction.vin.length === 0
  ) {
    return false;
  }
  for (const input of transaction.vin) {
    if (
      !input ||
      typeof input !== "object" ||
      !input.txid ||
      !input.vout ||
      input.vout < 0
    ) {
      return false;
    }
  }

  // Validate outputs
  if (
    !transaction.vout ||
    !Array.isArray(transaction.vout) ||
    transaction.vout.length === 0
  ) {
    return false;
  }
  for (const output of transaction.vout) {
    if (
      !output ||
      typeof output !== "object" ||
      !output.scriptpubkey ||
      !output.value ||
      output.value < 0
    ) {
      return false;
    }
  }

  // Validate transaction hash
  const serializedTransaction = JSON.stringify(transaction);
  const calculatedTxid = hash256(serializedTransaction);
  if (calculatedTxid !== transaction.txid) {
    return false;
  }

  // Add more validation logic as needed

  return true;
};

/**
 * Mine a block by finding a hash below the target difficulty.
 * @param {Object[]} transactions The array of validated transactions.
 * @param {string} coinbaseTx The serialized coinbase transaction.
 * @param {string} merkleRoot The merkle root of the transactions.
 * @returns {string} The mined block header.
 */
const mineBlock = (transactions, coinbaseTx, merkleRoot) => {
  let nonce = 0;
  let header;
  let hash;

  do {
    header = constructBlock(transactions, coinbaseTx, merkleRoot, nonce);
    hash = hash256(header);
    nonce++;
  } while (
    parseInt(hash, 16) >=
    parseInt(
      "0000ffff00000000000000000000000000000000000000000000000000000000",
      16
    )
  ); // Check if hash meets difficulty target

  return header;
};

/**
 * Construct a block.
 * @param {string} coinbaseTxHex The serialized coinbase transaction.
 * @param {string[]} txids The transaction IDs (txids) of the transactions to include in the block.
 * @param {string} prevBlockHash The hash of the previous block.
 * @param {number} timestamp The timestamp of the block.
 * @param {number} version The version of the block.
 * @param {number} nonce The nonce of the block.
 * @returns {string} The constructed block header.
 */
const constructBlock = (
  coinbaseTxHex,
  txids,
  prevBlockHash,
  timestamp,
  version,
  nonce
) => {
  // Construct the block header
  const blockHeader = [
    version.toString(16).padStart(8, "0"), // Version
    prevBlockHash, // Previous block hash
    generateMerkleRoot(txids), // Merkle root of transactions
    timestamp.toString(16).padStart(8, "0"), // Timestamp
    "1f00ffff", // Bits
    nonce.toString(16).padStart(8, "0"), // Nonce
  ].join("");

  // Serialize the coinbase transaction
  const coinbaseTx = Transaction.fromHex(coinbaseTxHex).toHex();

  // Calculate the hash of the coinbase transaction
  const coinbaseTxHash = hash256(coinbaseTx);

  // Construct the block header with the coinbase transaction hash
  const fullBlockHeader = blockHeader + coinbaseTxHash;

  return fullBlockHeader;
};

module.exports = { mineBlock, validateTransaction, constructBlock };
