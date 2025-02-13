// trade-api.js

require('dotenv').config();

const express = require('express');
const bodyParser = require('body-parser');
const fetch = require('node-fetch'); // For calling Jupiter's API
const crypto = require('crypto');
const bs58 = require('bs58');
const mongoose = require('mongoose');
const {
  Connection,
  Keypair,
  PublicKey,
  LAMPORTS_PER_SOL,
  Transaction,
  sendAndConfirmTransaction
} = require('@solana/web3.js');

const User = require('./models/User');

const app = express();
app.use(bodyParser.json());

// Load configuration from .env
const SOLANA_RPC_URL = process.env.SOLANA_RPC_URL || 'https://api.devnet.solana.com';
const PORT = process.env.PORT || 3001;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/solana-bot';
const API_KEY = process.env.API_KEY;
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;

// Verify required env variables
if (!API_KEY) {
  console.error("Missing API_KEY in environment variables");
  process.exit(1);
}
if (!ENCRYPTION_KEY) {
  console.error("Missing ENCRYPTION_KEY in environment variables");
  process.exit(1);
}
const encryptionKeyBuffer = Buffer.from(ENCRYPTION_KEY, 'hex');
if (encryptionKeyBuffer.length !== 32) {
  console.error("ENCRYPTION_KEY must be 32 bytes in hex");
  process.exit(1);
}

// Connect to MongoDB
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  });

const connection = new Connection(SOLANA_RPC_URL, 'confirmed');

/**
 * Middleware: Check for valid API key.
 */
function checkApiKey(req, res, next) {
  const providedKey = req.headers['x-api-key'];
  if (!providedKey || providedKey !== API_KEY) {
    return res.status(401).json({ error: 'Unauthorized: Invalid API key' });
  }
  next();
}
app.use(checkApiKey);

/**
 * Encryption helper functions using AES-256-CBC.
 * We generate a random IV for each encryption and store it with the ciphertext.
 */
function encryptSecret(plainText) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', encryptionKeyBuffer, iv);
  let encrypted = cipher.update(plainText, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  // Return IV and ciphertext joined by a colon.
  return iv.toString('base64') + ':' + encrypted;
}

function decryptSecret(encryptedText) {
  const parts = encryptedText.split(':');
  if (parts.length !== 2) {
    throw new Error("Invalid encrypted text format");
  }
  const iv = Buffer.from(parts[0], 'base64');
  const encrypted = parts[1];
  const decipher = crypto.createDecipheriv('aes-256-cbc', encryptionKeyBuffer, iv);
  let decrypted = decipher.update(encrypted, 'base64', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

/**
 * Helper to decode a secret key from base58 string.
 */
function decodeKeypairSecret(base58Str) {
  return bs58.decode(base58Str);
}

/**
 * Jupiter Integration: Get a swap transaction (base64 encoded) from Jupiter.
 * @param {PublicKey} userPublicKey - The user's wallet public key.
 * @param {string} inputMint - Mint address of token to swap from.
 * @param {string} outputMint - Mint address of token to swap to.
 * @param {number} amount - Amount in smallest unit.
 * @param {number} slippage - Acceptable slippage percentage (e.g., 0.5).
 * @returns {Promise<string>} - Base64 encoded swap transaction.
 */
async function getJupiterSwapTransaction(userPublicKey, inputMint, outputMint, amount, slippage) {
  const quoteUrl = `https://quote-api.jup.ag/v1/quote?inputMint=${inputMint}&outputMint=${outputMint}&amount=${amount}&slippage=${slippage}&onlyDirectRoutes=false`;
  const quoteResponse = await fetch(quoteUrl);
  if (!quoteResponse.ok) {
    throw new Error(`Jupiter quote API error: ${quoteResponse.statusText}`);
  }
  const quoteData = await quoteResponse.json();
  if (!quoteData.routes || quoteData.routes.length === 0) {
    throw new Error("No swap routes found from Jupiter.");
  }
  const route = quoteData.routes[0];
  const swapUrl = 'https://quote-api.jup.ag/v1/swap';
  const swapResponse = await fetch(swapUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      route: route,
      userPublicKey: userPublicKey.toString()
    })
  });
  if (!swapResponse.ok) {
    throw new Error(`Jupiter swap API error: ${swapResponse.statusText}`);
  }
  const swapData = await swapResponse.json();
  if (!swapData.swapTransaction) {
    throw new Error("Failed to obtain swap transaction from Jupiter.");
  }
  return swapData.swapTransaction;
}

/**
 * POST /api/buy
 * Secure endpoint to execute a buy (swap) order.
 * Expected JSON payload:
 * {
 *   "telegramId": "<user's Telegram ID>",
 *   "tradeAmount": 0.1,         // In SOL (or token units)
 *   "slippage": 0.5,            // e.g., 0.5 for 0.5%
 *   "inputMint": "<mint address to swap from>",
 *   "outputMint": "<mint address to swap to>"
 * }
 * The endpoint will look up the user by telegramId, decrypt the active wallet's secret key,
 * and execute the swap transaction via Jupiter.
 */
app.post('/api/buy', async (req, res) => {
  try {
    const { telegramId, tradeAmount, slippage, inputMint, outputMint } = req.body;
    if (!telegramId || !tradeAmount || !slippage || !inputMint || !outputMint) {
      return res.status(400).json({ error: 'Missing required fields.' });
    }
    const user = await User.findOne({ telegramId });
    if (!user || !user.wallets.length) {
      return res.status(400).json({ error: 'User not found or no wallets available.' });
    }
    const activeWallet = user.wallets[user.activeWalletIndex];
    const publicKey = new PublicKey(activeWallet.publicKey);
    const decryptedSecret = decryptSecret(activeWallet.secretKey);
    const userKeypair = Keypair.fromSecretKey(decodeKeypairSecret(decryptedSecret));
    if (userKeypair.publicKey.toString() !== publicKey.toString()) {
      return res.status(500).json({ error: 'Wallet decryption error: public key mismatch.' });
    }
    const amount = Math.floor(tradeAmount * LAMPORTS_PER_SOL);
    const swapTxBase64 = await getJupiterSwapTransaction(userKeypair.publicKey, inputMint, outputMint, amount, slippage);
    const swapTxBuffer = Buffer.from(swapTxBase64, 'base64');
    let swapTransaction = Transaction.from(swapTxBuffer);
    swapTransaction.partialSign(userKeypair);
    const signature = await connection.sendRawTransaction(swapTransaction.serialize());
    await connection.confirmTransaction(signature, 'confirmed');
    return res.json({ success: true, signature });
  } catch (error) {
    console.error('Error in /api/buy:', error);
    return res.status(500).json({ error: error.message });
  }
});

/**
 * POST /api/sell
 * Secure endpoint to execute a sell (swap) order.
 * Expected JSON payload (similar to /api/buy, but for selling).
 */
app.post('/api/sell', async (req, res) => {
  try {
    const { telegramId, tradeAmount, slippage, inputMint, outputMint } = req.body;
    if (!telegramId || !tradeAmount || !slippage || !inputMint || !outputMint) {
      return res.status(400).json({ error: 'Missing required fields.' });
    }
    const user = await User.findOne({ telegramId });
    if (!user || !user.wallets.length) {
      return res.status(400).json({ error: 'User not found or no wallets available.' });
    }
    const activeWallet = user.wallets[user.activeWalletIndex];
    const publicKey = new PublicKey(activeWallet.publicKey);
    const decryptedSecret = decryptSecret(activeWallet.secretKey);
    const userKeypair = Keypair.fromSecretKey(decodeKeypairSecret(decryptedSecret));
    if (userKeypair.publicKey.toString() !== publicKey.toString()) {
      return res.status(500).json({ error: 'Wallet decryption error: public key mismatch.' });
    }
    const amount = Math.floor(tradeAmount * LAMPORTS_PER_SOL);
    const swapTxBase64 = await getJupiterSwapTransaction(userKeypair.publicKey, inputMint, outputMint, amount, slippage);
    const swapTxBuffer = Buffer.from(swapTxBase64, 'base64');
    let swapTransaction = Transaction.from(swapTxBuffer);
    swapTransaction.partialSign(userKeypair);
    const signature = await connection.sendRawTransaction(swapTransaction.serialize());
    await connection.confirmTransaction(signature, 'confirmed');
    return res.json({ success: true, signature });
  } catch (error) {
    console.error('Error in /api/sell:', error);
    return res.status(500).json({ error: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`Secure Trade API server running on port ${PORT}`);
});