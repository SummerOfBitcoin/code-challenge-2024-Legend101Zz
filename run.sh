

# Install secp256k1 module
npm install secp256k1

# Check if installation was successful
if [ $? -ne 0 ]; then
  echo "Error: Failed to install secp256k1 module"
  exit 1
fi

# Run index.js
node index.js
