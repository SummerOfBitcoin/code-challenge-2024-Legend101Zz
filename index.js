const fs = require("fs");
// const { validateTransaction } = require("./validateTransaction");
const {
  constructBlock,
  mineBlock,
  validateTransaction,
} = require("./blockFunctions");

// Step 1: Read Transactions from Mempool
const mempoolDir = "./mempool";
const transactions = fs
  .readdirSync(mempoolDir)
  .filter((file) => file.endsWith(".json"))
  .map((file) => JSON.parse(fs.readFileSync(`${mempoolDir}/${file}`, "utf8")));

console.log(transactions);
// Step 2: Validate Transactions and Filter Valid Ones
const validTransactions = [];
transactions.forEach((transaction, index) => {
  try {
    if (!transaction) {
      // console.error(`Invalid transaction at index ${index}: undefined`);
    }
    const isValid = validateTransaction(transaction);
    if (isValid) {
      validTransactions.push(transaction);
    } else {
      console.error(
        `Invalid transaction at index ${index}: ${transaction.txid}`
      );
    }
  } catch (error) {
    console.error(
      `Error validating transaction at index ${index}: ${error.message}`
    );
  }
});

// Step 3: Construct the Block
const block = constructBlock(validTransactions);

// Step 4: Mine the Block
const minedBlock = mineBlock(block);

// Step 5: Output the Block to output.txt
fs.writeFileSync("output.txt", JSON.stringify(minedBlock));
