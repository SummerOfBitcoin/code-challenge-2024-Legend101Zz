const crypto = require("crypto");
const { validateScript, verifySignature } = require("./utils/validationUtils");

/**
 * Validate a transaction.
 * @param {Object} transaction The transaction object.
 * @param {Array} mempool The array of transactions in the mempool.
 * @param {Array} blockTransactions The array of transactions in the block.
 * @throws {Error} If the transaction is invalid.
 */
const validateTransaction = (transaction, mempool, blockTransactions) => {
  // Step 1: Size Check
  const transactionSize = JSON.stringify(transaction).length;
  if (transactionSize > MAX_TRANSACTION_SIZE) {
    throw new Error("Transaction size exceeds standard size limit");
  }

  // Step 2: Uniqueness Check
  const allTransactions = [...mempool, ...blockTransactions];
  const isDuplicate = allTransactions.some(
    (tx) => tx.txid === transaction.txid
  );
  if (isDuplicate) {
    throw new Error("Transaction is already present in the mempool or block");
  }

  // Step 7: Transaction Fee Check
  const totalInputValue = transaction.vin.reduce(
    (acc, input) => acc + input.prevout.value,
    0
  );
  const totalOutputValue = transaction.vout.reduce(
    (acc, output) => acc + output.value,
    0
  );
  const transactionFee = totalInputValue - totalOutputValue;
  if (transactionFee < MIN_TRANSACTION_FEE) {
    throw new Error("Transaction fee is too low");
  }

  // Step 8: Script Validation
  for (const input of transaction.vin) {
    const isValidScript = validateScript(
      input.scriptsig,
      input.prevout.scriptpubkey,
      transaction
    );
    if (!isValidScript) {
      throw new Error("Invalid script");
    }
  }

  // Step 10: Output Value Range Check
  for (const output of transaction.vout) {
    if (output.value <= 0 || output.value > MAX_OUTPUT_VALUE) {
      throw new Error("Output value is not within the legal money range");
    }
  }

  // Step 11: ScriptPubKey and ScriptSig Validation
  for (const input of transaction.vin) {
    const isValidSignature = verifySignature(
      input.scriptsig,
      input.witness,
      input.prevout.scriptpubkey
    );
    if (!isValidSignature) {
      throw new Error("Invalid signature");
    }
  }

  // Step 12: Minimum Input Requirement
  if (transaction.vin.length < MIN_INPUT_COUNT) {
    throw new Error("Transaction must have at least one input");
  }

  return true; // Transaction is valid
};

// Constants
const MAX_TRANSACTION_SIZE = 950000; // Maximum transaction size slightly below the maximum block size

const MIN_TRANSACTION_FEE = 1000; // Placeholder value for the minimum transaction fee (adjust based on network fee rates)

const MAX_OUTPUT_VALUE = 21e6; // Maximum output value set to Bitcoin's maximum supply

const MIN_INPUT_COUNT = 1; // Minimum input count required in a transaction

module.exports = { validateTransaction };
