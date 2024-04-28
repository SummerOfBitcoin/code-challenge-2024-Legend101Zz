const crypto = require("crypto");
/**
 * Validates the scriptPubKey and scriptSig to ensure the spending script is accepted.
 * @param {string[]} scriptSig The scriptSig (unlocking script).
 * @param {string} scriptPubKey The scriptPubKey (locking script).
 * @param {object} tx The transaction object.
 * @returns {boolean} True if the scripts are valid, otherwise false.
 */
const validateScript = (scriptSig, scriptPubKey, tx) => {
  try {
    const stack = [];
    const inputs = tx.vin;
    const outputs = tx.vout;

    // If SegWit transaction, execute witness data
    if (tx.witness && tx.witness.length > 0) {
      for (let i = 0; i < inputs.length; i++) {
        const input = inputs[i];
        const witnessData = tx.witness[i] || [];
        const sigScript = parseScript(input.scriptsig);
        const combinedScript = sigScript.concat(witnessData);
        executeScript(combinedScript, stack);
      }
    } else {
      // If not SegWit, execute scriptSig
      const sigScript = parseScript(scriptSig);
      executeScript(sigScript, stack);
    }

    // Check if the final stack is truthy
    return stack.length === 1 && stack[0] === true;
  } catch (error) {
    console.error("Script validation error:", error);
    return false;
  }
};
/**
 * Parses the script into individual opcodes.
 * @param {string} script The script to parse.
 * @returns {Array} An array of opcodes.
 */
const parseScript = (script) => {
  console.log("OP CODE", script.split(" "));
  // Split the script into individual opcodes
  return script.split(" ");
};
/**
 * Executes the script using a stack-based interpreter.
 * @param {Array} script The parsed script to execute.
 * @param {Array} stack The stack used for execution.
 */
const executeScript = (script, stack) => {
  for (let i = 0; i < script.length; i++) {
    const opcode = script[i];
    // Convert the opcode hex string to a number
    const opcodeByte = parseInt(opcode, 16);
    if (opcodeByte === 172) {
      // OP_CHECKSIG
      const pubkey = stack.pop();
      const signature = stack.pop();
      const isValid = checkSignature(signature, pubkey);
      stack.push(isValid);
    } else if (opcodeByte === 169) {
      // OP_HASH160
      const data = stack.pop();
      const hash = crypto.createHash("sha256").update(data).digest();
      const ripemd160 = crypto
        .createHash("ripemd160")
        .update(hash)
        .digest("hex");
      stack.push(ripemd160);
    } else if (opcodeByte === 135) {
      // OP_EQUALVERIFY
      const item1 = stack.pop();
      const item2 = stack.pop();
      if (item1 !== item2) {
        throw new Error("OP_EQUALVERIFY failed");
      }
    } else if (opcodeByte === 118) {
      // OP_DUP
      const item = stack[stack.length - 1];
      stack.push(item);
    } else if (opcodeByte === 170) {
      // OP_HASH256
      const data = stack.pop();
      const hash = crypto.createHash("sha256").update(data).digest();
      const doubleHash = crypto.createHash("sha256").update(hash).digest("hex");
      stack.push(doubleHash);
    } else if (opcodeByte === 135) {
      // OP_EQUAL
      const item1 = stack.pop();
      const item2 = stack.pop();
      stack.push(item1 === item2);
    } else if (opcodeByte === 105) {
      // OP_VERIFY
      const item = stack.pop();
      if (!item) {
        throw new Error("OP_VERIFY failed");
      }
    } else {
      // Push the opcode onto the stack
      stack.push(opcode);
    }
  }
};

/**
 * Verifies the signature against the public key.
 * @param {string} scriptSig The scriptSig containing the signature.
 * @param {string} witness The witness containing additional data (if any).
 * @param {string} scriptPubKey The scriptPubKey containing the public key.
 * @returns {boolean} True if the signature is valid, otherwise false.
 */
const verifySignature = (scriptSig, witness, scriptPubKey) => {
  // Assuming the signature is in the first element of the scriptSig array
  const signature = scriptSig[0];

  // Assuming the public key is in the second element of the scriptSig array
  const publicKey = scriptSig[1];

  // Assuming the message to be signed is the scriptPubKey
  const message = scriptPubKey;

  // Assuming the hashing algorithm used is SHA256
  const hash = crypto.createHash("sha256").update(message).digest("hex");

  // Assuming the signature verification logic using the public key and signature
  // Example: Use crypto module to verify the signature
  const verifier = crypto.createVerify("SHA256");
  verifier.update(hash);
  const isSignatureValid = verifier.verify(publicKey, signature, "hex");

  return isSignatureValid;
};

module.exports = { validateScript, verifySignature };
