/**
 * VIGIL Normalizer — Pre-scan text normalization
 *
 * Decodes obfuscation layers before pattern matching:
 *   1. Base64 detection and decode
 *   2. Unicode normalization (NFKC — collapses lookalikes)
 *   3. Zero-width character stripping
 *   4. Homoglyph collapse (Cyrillic/Greek → Latin)
 *   5. HTML entity decode
 *   6. Hex/unicode escape decode
 *   7. Whitespace collapse
 *
 * Returns the original text + all decoded layers concatenated,
 * so the scanner sees both the raw input and its deobfuscated form.
 *
 * Zero external dependencies.
 */

// ── Zero-width characters ──────────────────────────────────────────────────
const ZERO_WIDTH_RE = /[\u200B\u200C\u200D\u200E\u200F\uFEFF\u00AD\u2060\u180E]/g;

// ── Homoglyph map (Cyrillic/Greek → Latin lookalikes) ──────────────────────
const HOMOGLYPHS = {
  // Cyrillic — full lookalike coverage
  "\u0410": "A", "\u0412": "B", "\u0421": "C", "\u0415": "E",
  "\u041D": "H", "\u0406": "I", "\u041A": "K", "\u041C": "M",
  "\u041E": "O", "\u0420": "P", "\u0405": "S", "\u0422": "T",
  "\u0425": "X", "\u0408": "J",
  "\u0430": "a", "\u0435": "e", "\u0456": "i", "\u0458": "j",
  "\u043E": "o", "\u0440": "p", "\u0455": "s", "\u0441": "c",
  "\u0443": "y", "\u0445": "x", "\u044C": "b", "\u0501": "d",
  "\u051B": "q", "\u04BB": "h", "\u0457": "i",
  // Greek — full lookalike coverage
  "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0397": "H",
  "\u0399": "I", "\u039A": "K", "\u039C": "M", "\u039D": "N",
  "\u039F": "O", "\u03A1": "P", "\u03A4": "T", "\u03A7": "X",
  "\u03B1": "a", "\u03B5": "e", "\u03B9": "i", "\u03BF": "o",
  "\u03C1": "p", "\u03BD": "v", "\u03C9": "w",
  // Common fullwidth substitutions
  "\uFF21": "A", "\uFF22": "B", "\uFF23": "C", "\uFF24": "D",
  "\uFF25": "E", "\uFF26": "F", "\uFF27": "G", "\uFF28": "H",
  "\uFF29": "I", "\uFF2A": "J", "\uFF2B": "K", "\uFF2C": "L",
  "\uFF2D": "M", "\uFF2E": "N", "\uFF2F": "O", "\uFF30": "P",
  "\uFF41": "a", "\uFF42": "b", "\uFF43": "c", "\uFF44": "d",
  "\uFF45": "e", "\uFF46": "f", "\uFF47": "g", "\uFF48": "h",
  "\uFF49": "i", "\uFF4A": "j", "\uFF4B": "k", "\uFF4C": "l",
  "\uFF4D": "m", "\uFF4E": "n", "\uFF4F": "o", "\uFF50": "p",
  // Dashes and punctuation lookalikes
  "\u2010": "-", "\u2011": "-", "\u2012": "-", "\u2013": "-",
  "\u2014": "-",
};

const HOMOGLYPH_RE = new RegExp("[" + Object.keys(HOMOGLYPHS).join("") + "]", "g");

// ── HTML entity decode ─────────────────────────────────────────────────────
const HTML_NAMED = {
  "&lt;": "<", "&gt;": ">", "&amp;": "&", "&quot;": '"',
  "&apos;": "'", "&nbsp;": " ", "&tab;": "\t",
};

function decodeHtmlEntities(text) {
  // Named entities
  let result = text.replace(/&\w+;/g, (match) => HTML_NAMED[match.toLowerCase()] || match);
  // Numeric &#123; or &#x7B;
  result = result.replace(/&#x([0-9a-fA-F]+);/g, (_, hex) => {
    const code = parseInt(hex, 16);
    return code > 0 && code < 0x110000 ? String.fromCodePoint(code) : "";
  });
  result = result.replace(/&#(\d+);/g, (_, dec) => {
    const code = parseInt(dec, 10);
    return code > 0 && code < 0x110000 ? String.fromCodePoint(code) : "";
  });
  return result;
}

// ── Hex / unicode escape decode ────────────────────────────────────────────
function decodeEscapes(text) {
  let result = text;
  // \x41 hex escapes
  result = result.replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) =>
    String.fromCharCode(parseInt(hex, 16))
  );
  // \u0041 unicode escapes
  result = result.replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) =>
    String.fromCharCode(parseInt(hex, 16))
  );
  return result;
}

// ── Base64 detection and decode ────────────────────────────────────────────
// Match base64 strings that are at least 20 chars (short ones are noisy)
const BASE64_RE = /[A-Za-z0-9+/]{20,}={0,2}/g;

function isLikelyBase64(str) {
  if (str.length < 20) return false;
  if (str.length % 4 !== 0 && !str.endsWith("=")) return false;
  // Must have mix of upper, lower, digits
  if (!/[A-Z]/.test(str) || !/[a-z]/.test(str) || !/[0-9]/.test(str)) return false;
  return true;
}

function decodeBase64Segments(text) {
  const decoded = [];
  const matches = text.match(BASE64_RE) || [];

  for (const match of matches) {
    if (!isLikelyBase64(match)) continue;
    try {
      const buf = Buffer.from(match, "base64");
      const str = buf.toString("utf8");
      // Only keep if it decodes to printable ASCII/UTF-8
      if (/^[\x20-\x7E\t\n\r]+$/.test(str) && str.length >= 4) {
        decoded.push(str);
      }
    } catch {
      // Not valid base64, skip
    }
  }

  return decoded;
}

// ── Main normalizer ────────────────────────────────────────────────────────

/**
 * Normalize text through all deobfuscation layers.
 * Returns an object with the original text and all decoded layers.
 *
 * @param {string} text — Raw input
 * @returns {{ original: string, normalized: string, variants: string[], wasObfuscated: boolean, decodedLayers: string[], combined: string }}
 */
function normalize(text) {
  if (!text || typeof text !== "string") {
    return { original: "", normalized: "", variants: [], wasObfuscated: false, decodedLayers: [], combined: "" };
  }

  const original = text;
  const decodedLayers = [];

  // Layer 1: Strip zero-width characters
  let normalized = text.replace(ZERO_WIDTH_RE, "");

  // Layer 2: Unicode NFKC normalization (collapses fullwidth, compatibility chars)
  normalized = normalized.normalize("NFKC");

  // Layer 3: Homoglyph collapse
  normalized = normalized.replace(HOMOGLYPH_RE, (ch) => HOMOGLYPHS[ch] || ch);

  // Layer 4: HTML entity decode
  const htmlDecoded = decodeHtmlEntities(normalized);
  if (htmlDecoded !== normalized) {
    decodedLayers.push(htmlDecoded);
    normalized = htmlDecoded;
  }

  // Layer 5: Hex/unicode escape decode
  const escDecoded = decodeEscapes(normalized);
  if (escDecoded !== normalized) {
    decodedLayers.push(escDecoded);
    normalized = escDecoded;
  }

  // Layer 6: Collapse whitespace (multiple spaces, tabs, etc.)
  normalized = normalized.replace(/\s+/g, " ").trim();

  // Layer 7: Base64 decode (append decoded segments — don't replace original)
  const base64Decoded = decodeBase64Segments(text);
  if (base64Decoded.length > 0) {
    decodedLayers.push(...base64Decoded);
  }

  // Generate Unicode normalization variants (NFC, NFD, NFKC, NFKD)
  const unicodeVariants = [];
  try {
    unicodeVariants.push(normalized.normalize("NFC"));
    unicodeVariants.push(normalized.normalize("NFD"));
    unicodeVariants.push(normalized.normalize("NFKC"));
    unicodeVariants.push(normalized.normalize("NFKD"));
  } catch (e) {
    // Fallback if normalize fails
    unicodeVariants.push(normalized);
  }

  // Collect all variants (deduplicated)
  const allVariants = [...new Set([normalized, ...decodedLayers, ...unicodeVariants])];

  // Detect if obfuscation was used
  const wasObfuscated =
    normalized !== original ||
    decodedLayers.length > 0 ||
    ZERO_WIDTH_RE.test(original) ||
    base64Decoded.length > 0;

  // Combined: original + normalized + decoded layers (scanner sees everything)
  // Original is included so obfuscation patterns still fire on raw input
  const combined = [original, normalized, ...decodedLayers].join("\n");

  return {
    original,
    normalized,
    variants: allVariants,
    wasObfuscated,
    decodedLayers,
    combined
  };
}

module.exports = {
  normalize,
  // Exposed for testing
  decodeBase64Segments,
  decodeHtmlEntities,
  decodeEscapes,
  ZERO_WIDTH_RE,
  HOMOGLYPHS,
};
