/**
 * License validator for correctover-scan NPM.
 * Mirrors the Python LicenseValidator: 50 free scans/day, CORRECTOVER_LICENSE_KEY unlocks.
 * Supports CV-TRL/CV-PRO (FC) and COV- (Cloud) key formats.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');

const FREE_LIMIT_PER_DAY = 50;
const STATE_FILE = path.join(os.homedir(), '.correctover', 'license.json');

function loadState() {
  try {
    if (fs.existsSync(STATE_FILE)) {
      return JSON.parse(fs.readFileSync(STATE_FILE, 'utf-8'));
    }
  } catch (e) {}
  return { products: {}, license_key: null, installed_at: Date.now() / 1000 };
}

function saveState(state) {
  try {
    fs.mkdirSync(path.dirname(STATE_FILE), { recursive: true });
    fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
  } catch (e) {}
}

function getProductState(state, product) {
  const today = new Date().toISOString().slice(0, 10);
  if (!state.products[product]) {
    state.products[product] = { calls_today: 0, date: today, total_calls: 0 };
  }
  if (state.products[product].date !== today) {
    state.products[product].calls_today = 0;
    state.products[product].date = today;
  }
  return state.products[product];
}

function verifyLicenseKey(key) {
  if (!key || key.length < 12) return false;

  // COV-<product>-<hash> (Cloud HMAC)
  if (key.startsWith('COV-')) {
    const parts = key.split('-');
    if (parts.length < 3) return false;
    const productCode = parts.slice(1, -1).join('-');
    const secret = `correctover-${productCode}-2026`;
    const expected = crypto.createHash('sha256').update(secret).digest('hex').slice(0, 12);
    return parts[parts.length - 1].startsWith(expected);
  }

  // CV-TRL-<base64> / CV-PRO-<base64> (FC XunhuPay)
  if (key.startsWith('CV-')) {
    const parts = key.split('-', 2);
    if (parts.length < 3) return false;
    try {
      let payload = parts[2];
      const dot = payload.indexOf('.');
      if (dot > 0) payload = payload.substring(0, dot);
      const decoded = Buffer.from(payload, 'base64url').toString();
      return decoded.includes('@') || decoded.length > 10;
    } catch (e) {
      return false;
    }
  }

  return false;
}

function checkLicense(product) {
  const state = loadState();
  const ps = getProductState(state, product);
  const licenseKey = state.license_key || process.env.CORRECTOVER_LICENSE_KEY;

  if (licenseKey && verifyLicenseKey(licenseKey)) {
    return {
      authorized: true,
      tier: 'pro',
      calls_remaining: Infinity,
      calls_today: ps.calls_today,
      limit: Infinity,
    };
  }

  const remaining = Math.max(0, FREE_LIMIT_PER_DAY - ps.calls_today);
  return {
    authorized: remaining > 0,
    tier: 'free',
    calls_remaining: remaining,
    calls_today: ps.calls_today,
    limit: FREE_LIMIT_PER_DAY,
  };
}

function recordCall(product) {
  const state = loadState();
  const status = checkLicense(product);
  if (!status.authorized) return status;

  const ps = getProductState(state, product);
  ps.calls_today += 1;
  ps.total_calls = (ps.total_calls || 0) + 1;
  saveState(state);

  status.calls_remaining = Math.max(0, status.limit - ps.calls_today);
  status.calls_today = ps.calls_today;
  return status;
}

function getUpgradeMessage(status) {
  if (status.tier !== 'free') return '';
  if (status.calls_remaining <= 0) {
    return `\n🚫 Free tier limit reached (${FREE_LIMIT_PER_DAY} scans/day).\n   Upgrade: https://correctover.com/checkout\n   Or: export CORRECTOVER_LICENSE_KEY=<your-key>\n`;
  }
  return `\n📊 Free tier: ${status.calls_remaining} scans remaining today.\n   Upgrade: https://correctover.com/checkout\n`;
}

module.exports = {
  FREE_LIMIT_PER_DAY,
  checkLicense,
  recordCall,
  getUpgradeMessage,
  verifyLicenseKey,
};
