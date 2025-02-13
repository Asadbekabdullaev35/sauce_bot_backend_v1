// models/User.js
const mongoose = require('mongoose');

const WalletSchema = new mongoose.Schema({
  label: { type: String, default: 'Unnamed Wallet' },
  publicKey: { type: String, required: true },
  // Store the secret key as an encrypted string.
  secretKey: { type: String, required: true }
});

const SettingsSchema = new mongoose.Schema({
  buy: {
    slippage: { type: Number, default: 0.5 },
    tradeAmount: { type: Number, default: 0.1 }
  },
  sell: {
    slippage: { type: Number, default: 0.5 },
    tradeAmount: { type: Number, default: 0.1 }
  }
});

const UserSchema = new mongoose.Schema({
  telegramId: { type: String, required: true, unique: true },
  wallets: [WalletSchema],
  activeWalletIndex: { type: Number, default: 0 },
  settings: { type: SettingsSchema, default: () => ({}) }
});

module.exports = mongoose.model('User', UserSchema);