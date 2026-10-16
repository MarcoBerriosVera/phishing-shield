/**
 * vault-crypto.js — Phishing Shield Password Manager
 *
 * Architecture: Envelope Encryption
 *   Master password ──PBKDF2──► KEK (Key Encryption Key)
 *   Random 256-bit  ──────────► DEK (Data Encryption Key)
 *   DEK encrypted with KEK  → stored on vault server
 *   Vault blob encrypted with DEK → stored on vault server
 *
 * Algorithms:
 *   Key derivation : PBKDF2-HMAC-SHA256, 600 000 iterations, 16-byte salt
 *   Symmetric enc  : AES-256-GCM (authenticated — integrity included)
 *   2FA            : TOTP / RFC 6238 (HMAC-SHA1, 30-second window)
 *   RNG            : crypto.getRandomValues (CSPRNG)
 *
 * All operations are async and use the native Web Crypto API exclusively.
 * No external dependencies.
 */

'use strict';

// ── Constants ─────────────────────────────────────────────────────────────────
const PBKDF2_ITERATIONS = 600_000;
const PBKDF2_HASH       = 'SHA-256';
const AES_KEY_BITS      = 256;
const SALT_BYTES        = 16;
const IV_BYTES          = 12; // 96-bit IV recommended for AES-GCM

// ── Random helpers ────────────────────────────────────────────────────────────
export function randomBytes(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}

// ── Base64 helpers ────────────────────────────────────────────────────────────
export function bytesToBase64(bytes) {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

export function base64ToBytes(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// ── PBKDF2 key derivation ─────────────────────────────────────────────────────
/**
 * Derive KEK from master password + salt.
 * Returns a non-extractable AES-GCM CryptoKey (only used to wrap/unwrap DEK).
 */
export async function deriveKEK(masterPassword, saltB64) {
  const passBytes = new TextEncoder().encode(masterPassword);
  const salt      = base64ToBytes(saltB64);

  const baseKey = await crypto.subtle.importKey(
    'raw', passBytes, 'PBKDF2', false, ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: PBKDF2_HASH },
    baseKey,
    { name: 'AES-GCM', length: AES_KEY_BITS },
    false,             // KEK is never exported — only used in-memory
    ['encrypt', 'decrypt']
  );
}

/** Generate a fresh random PBKDF2 salt (base64). */
export function generateSalt() {
  return bytesToBase64(randomBytes(SALT_BYTES));
}

// ── DEK (Data Encryption Key) ─────────────────────────────────────────────────
/**
 * Generate a random 256-bit DEK.
 * Extractable so we can encrypt it with the KEK and persist it.
 */
export async function generateDEK() {
  return crypto.subtle.generateKey(
    { name: 'AES-GCM', length: AES_KEY_BITS },
    true,
    ['encrypt', 'decrypt']
  );
}

/** Wrap DEK with KEK → {enc, iv} both base64. */
export async function encryptDEK(dek, kek) {
  const iv     = randomBytes(IV_BYTES);
  const dekRaw = await crypto.subtle.exportKey('raw', dek);
  const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, kek, dekRaw);
  return { enc: bytesToBase64(new Uint8Array(cipher)), iv: bytesToBase64(iv) };
}

/** Unwrap DEK with KEK → CryptoKey (extractable for session export). */
export async function decryptDEK(encB64, ivB64, kek) {
  const enc    = base64ToBytes(encB64);
  const iv     = base64ToBytes(ivB64);
  const dekRaw = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, kek, enc);
  return crypto.subtle.importKey(
    'raw', dekRaw, { name: 'AES-GCM', length: AES_KEY_BITS },
    true, ['encrypt', 'decrypt']
  );
}

/** Export a DEK to base64 (for temporary session storage). */
export async function exportDEK(dek) {
  const raw = await crypto.subtle.exportKey('raw', dek);
  return bytesToBase64(new Uint8Array(raw));
}

/** Import a DEK from base64 (from session storage). */
export async function importDEK(b64) {
  const raw = base64ToBytes(b64);
  return crypto.subtle.importKey(
    'raw', raw, { name: 'AES-GCM', length: AES_KEY_BITS },
    false, ['encrypt', 'decrypt']
  );
}

// ── AES-256-GCM encrypt / decrypt ────────────────────────────────────────────
/** Encrypt a UTF-8 string with DEK → {enc, iv} both base64. */
export async function encryptData(dek, plaintext) {
  const iv      = randomBytes(IV_BYTES);
  const data    = new TextEncoder().encode(plaintext);
  const cipher  = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, dek, data);
  return { enc: bytesToBase64(new Uint8Array(cipher)), iv: bytesToBase64(iv) };
}

/** Decrypt base64 ciphertext with DEK → UTF-8 string. */
export async function decryptData(dek, encB64, ivB64) {
  const enc   = base64ToBytes(encB64);
  const iv    = base64ToBytes(ivB64);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, dek, enc);
  return new TextDecoder().decode(plain);
}

// ── TOTP / RFC 6238 ───────────────────────────────────────────────────────────
const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** Generate a random 20-byte TOTP secret encoded as base32. */
export function generateTOTPSecret() {
  const bytes = randomBytes(20);
  let result  = '';
  for (const b of bytes) result += BASE32_CHARS[b % 32];
  return result;
}

function base32ToBytes(secret) {
  const s    = secret.toUpperCase().replace(/=+$/, '');
  const bits = [...s].map(c => {
    const idx = BASE32_CHARS.indexOf(c);
    if (idx === -1) throw new Error(`Invalid base32 char: ${c}`);
    return idx.toString(2).padStart(5, '0');
  }).join('');

  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return new Uint8Array(bytes);
}

/** Compute TOTP code for a given timestamp (ms). */
export async function computeTOTP(secret, timestampMs = Date.now()) {
  const counter     = Math.floor(timestampMs / 1000 / 30);
  const counterBuf  = new ArrayBuffer(8);
  new DataView(counterBuf).setUint32(4, counter >>> 0, false); // big-endian

  const key = await crypto.subtle.importKey(
    'raw', base32ToBytes(secret),
    { name: 'HMAC', hash: 'SHA-1' },
    false, ['sign']
  );
  const hmac   = new Uint8Array(await crypto.subtle.sign('HMAC', key, counterBuf));
  const offset = hmac[19] & 0x0f;
  const code   = (
    ((hmac[offset]     & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8)  |
     (hmac[offset + 3] & 0xff)
  ) % 1_000_000;

  return code.toString().padStart(6, '0');
}

/**
 * Verify a TOTP code. Accepts ±1 window to tolerate clock drift.
 * Returns true if valid.
 */
export async function verifyTOTP(secret, code) {
  const padded = code.toString().padStart(6, '0');
  const now    = Date.now();
  for (const delta of [-1, 0, 1]) {
    if (await computeTOTP(secret, now + delta * 30_000) === padded) return true;
  }
  return false;
}

/** Build the otpauth URI for QR code / manual entry. */
export function buildOTPAuthURI(secret, label = 'PhishingShield') {
  return `otpauth://totp/${encodeURIComponent(label)}?secret=${secret}&issuer=PhishingShield&algorithm=SHA1&digits=6&period=30`;
}

// ── Secure password generator ─────────────────────────────────────────────────
const CHARSETS = {
  upper:   'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  lower:   'abcdefghijklmnopqrstuvwxyz',
  numbers: '0123456789',
  symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?',
};

/**
 * Generate a cryptographically secure random password.
 * Uses rejection sampling to eliminate modulo bias.
 */
export function generatePassword(length = 20, opts = {}) {
  const { upper = true, lower = true, numbers = true, symbols = true } = opts;
  let pool = '';
  const required = [];

  if (upper)   { pool += CHARSETS.upper;   required.push(CHARSETS.upper); }
  if (lower)   { pool += CHARSETS.lower;   required.push(CHARSETS.lower); }
  if (numbers) { pool += CHARSETS.numbers; required.push(CHARSETS.numbers); }
  if (symbols) { pool += CHARSETS.symbols; required.push(CHARSETS.symbols); }
  if (!pool)   pool = CHARSETS.lower;

  const poolLen  = pool.length;
  const limit    = 256 - (256 % poolLen); // rejection threshold

  let password = '';
  // Guarantee at least one char from each required charset
  for (const charset of required) {
    const [b] = randomBytes(1);
    password += charset[b % charset.length];
  }

  // Fill the rest with rejection sampling
  while (password.length < length) {
    const bytes = randomBytes(Math.ceil((length - password.length) * 1.5));
    for (const b of bytes) {
      if (b < limit && password.length < length) {
        password += pool[b % poolLen];
      }
    }
  }

  // Shuffle to avoid required chars always at the start
  const arr = password.split('');
  for (let i = arr.length - 1; i > 0; i--) {
    const [b] = randomBytes(1);
    const j   = b % (i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr.join('');
}

// ── Have I Been Pwned — k-anonymity check ─────────────────────────────────────
/**
 * Check if a password appears in known data breaches via HIBP Pwned Passwords.
 * Uses k-anonymity: only the first 5 hex chars of SHA-1 are sent to the server.
 * The full hash never leaves the browser.
 *
 * Returns the number of times the password was found (0 = not breached).
 * Returns -1 on network error (treat as unknown, not breached).
 */
export async function checkPwnedPassword(password) {
  try {
    const encoded  = new TextEncoder().encode(password);
    const hashBuf  = await crypto.subtle.digest('SHA-1', encoded);
    const hashHex  = Array.from(new Uint8Array(hashBuf))
                       .map(b => b.toString(16).padStart(2, '0'))
                       .join('').toUpperCase();

    const prefix   = hashHex.slice(0, 5);
    const suffix   = hashHex.slice(5);

    const resp = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
      signal: AbortSignal.timeout(5000),
      headers: { 'Add-Padding': 'true' }, // prevents traffic analysis via response size
    });
    if (!resp.ok) return -1;

    const text = await resp.text();
    for (const line of text.split('\r\n')) {
      const [s, count] = line.split(':');
      if (s === suffix) return parseInt(count, 10);
    }
    return 0; // not found in breach list
  } catch {
    return -1; // network error — fail open (don't block the user)
  }
}

/** Estimate password entropy in bits (used internally). */
export function passwordEntropy(password) {
  const hasUpper   = /[A-Z]/.test(password);
  const hasLower   = /[a-z]/.test(password);
  const hasNumbers = /[0-9]/.test(password);
  const hasSymbols = /[^A-Za-z0-9]/.test(password);
  let poolSize = 0;
  if (hasUpper)   poolSize += 26;
  if (hasLower)   poolSize += 26;
  if (hasNumbers) poolSize += 10;
  if (hasSymbols) poolSize += 32;
  return Math.floor(password.length * Math.log2(poolSize || 1));
}

// ── Smart password strength assessor ──────────────────────────────────────────
// Evaluates patterns that pure entropy misses: common passwords, keyboard walks,
// repeated characters, leet substitutions and date patterns.
// Returns { score: 0-4, label, color, suggestions: string[] }

const COMMON_PASSWORDS = new Set([
  '123456','password','12345678','qwerty','123456789','12345','1234567',
  'iloveyou','admin','welcome','monkey','dragon','master','abc123','letmein',
  'sunshine','princess','football','shadow','superman','michael','qwertyuiop',
  'password1','123123','111111','1234567890','qwerty123','password123',
  '1q2w3e4r','666666','123321','000000','zxcvbnm','asdfghjkl','qazwsx',
  'trustno1','baseball','batman','senha','contrasena','contraseña','clave',
  'hola123','chile123','admin123','root','toor','pass','test','login',
]);

const KEYBOARD_WALKS = [
  'qwertyuiop','asdfghjkl','zxcvbnm','1234567890',
  'qwerty','asdfgh','zxcvbn','1qaz2wsx','qazwsx',
];

const LEET_MAP = { '@':'a','3':'e','1':'i','0':'o','5':'s','7':'t','4':'a','$':'s' };

function deLeet(s) {
  return s.toLowerCase().split('').map(c => LEET_MAP[c] || c).join('');
}

function hasKeyboardWalk(s) {
  const lower = s.toLowerCase();
  return KEYBOARD_WALKS.some(walk => lower.includes(walk.slice(0, 5)));
}

function hasRepeats(s) {
  // 3+ of same char, or repeating pattern like "abcabc"
  if (/(.)\1{2,}/.test(s)) return true;
  if (s.length >= 6) {
    const half = s.slice(0, Math.floor(s.length / 2));
    if (s.toLowerCase().startsWith(half.toLowerCase() + half.toLowerCase().slice(0, 1))) return true;
  }
  return false;
}

function hasDatePattern(s) {
  // ddmmyyyy, mmddyyyy, yyyy, dd/mm/yy etc.
  return /\b(19|20)\d{2}\b/.test(s) ||
         /\b\d{2}[\/\-\.]\d{2}[\/\-\.]\d{2,4}\b/.test(s) ||
         /\b(0[1-9]|[12]\d|3[01])(0[1-9]|1[0-2])\d{2,4}\b/.test(s);
}

/**
 * Assess password strength beyond simple entropy.
 * Returns { score: 0-4, label, color, entropy, suggestions }
 */
export function assessPasswordStrength(password) {
  if (!password) return { score: 0, label: '—', color: '#64748b', entropy: 0, suggestions: [] };

  const lower       = password.toLowerCase();
  const deLeeted    = deLeet(password);
  const entropy     = passwordEntropy(password);
  const suggestions = [];

  let penalty = 0;

  // Common password check
  if (COMMON_PASSWORDS.has(lower) || COMMON_PASSWORDS.has(deLeeted)) {
    penalty += 3;
    suggestions.push('Esta contraseña está en listas de contraseñas comunes.');
  }

  // Keyboard walk
  if (hasKeyboardWalk(password)) {
    penalty += 2;
    suggestions.push('Evita secuencias de teclado (qwerty, asdf, 1234…).');
  }

  // Repeated characters or patterns
  if (hasRepeats(password)) {
    penalty += 1;
    suggestions.push('Evita caracteres o patrones repetidos (aaa, abcabc…).');
  }

  // Date pattern
  if (hasDatePattern(password)) {
    penalty += 1;
    suggestions.push('Evita incluir fechas — son fáciles de adivinar.');
  }

  // Too short
  if (password.length < 8)  { penalty += 2; suggestions.push('Usa al menos 8 caracteres.'); }
  if (password.length < 12) { suggestions.push('Idealmente 12 o más caracteres.'); }

  // Charset variety
  if (!/[A-Z]/.test(password)) suggestions.push('Agrega letras mayúsculas.');
  if (!/[0-9]/.test(password)) suggestions.push('Agrega números.');
  if (!/[^A-Za-z0-9]/.test(password)) suggestions.push('Agrega símbolos (!@#$…).');

  // Score: start from entropy, subtract penalties
  let score;
  if      (entropy < 30 || penalty >= 3) score = 0;
  else if (entropy < 50 || penalty >= 2) score = 1;
  else if (entropy < 70 || penalty >= 1) score = 2;
  else if (entropy < 90)                 score = 3;
  else                                   score = 4;

  const LABELS = ['Muy débil', 'Débil', 'Moderada', 'Fuerte', 'Muy fuerte'];
  const COLORS = ['#ef4444',  '#f97316', '#eab308', '#22c55e', '#00e5a0'];

  return {
    score,
    label:       LABELS[score],
    color:       COLORS[score],
    entropy,
    suggestions: suggestions.slice(0, 3), // max 3 tips
  };
}
