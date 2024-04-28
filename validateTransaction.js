// validateTransaction.js

/**
 * Validate a transaction.
 * @param {Object} transaction The transaction object.
 * @throws {Error} If the transaction is invalid.
 */
const validateTransaction = (transaction) => {
  // Validate version
  if (transaction.version !== 1 && transaction.version !== 2) {
    return false;
  }

  // Validate locktime
  if (transaction.locktime < 0 || transaction.locktime > 0xffffffff) {
    return false;
  }

  // Validate inputs
  for (const input of transaction.vin) {
    if (input.is_coinbase) {
      return false; // Coinbase transactions are not allowed
    }

    // Validate txid
    if (!/^[0-9a-fA-F]{64}$/.test(input.txid)) {
      return false;
    }

    // Validate vout
    if (input.vout < 0) {
      return false;
    }

    // Validate prevout
    const { prevout } = input;
    if (
      !prevout ||
      typeof prevout.scriptpubkey !== "string" ||
      !prevout.value ||
      prevout.value <= 0
    ) {
      return false;
    }

    // Validate scriptsig and witness (if present)
    if (!input.is_coinbase && (!input.scriptsig || !input.witness)) {
      return false;
    }
  }

  // Validate outputs
  for (const output of transaction.vout) {
    // Validate scriptpubkey
    if (typeof output.scriptpubkey !== "string") {
      return false;
    }

    // Validate value
    if (output.value <= 0) {
      return false;
    }
  }

  return true; // Transaction is valid
};

module.exports = { validateTransaction };
