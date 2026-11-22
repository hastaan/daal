// Daal update channel (specs/relaypack-v1.md, "Mirror provider
// appsscript"; docs/optional-addons-plan.md §3).
//
// One script per Google account, serving many relays. It keeps one small
// text per relay "slot", a daal-refresh-v2 container, and hands it to
// whoever asks for that slot with the slot's read token k. It never
// fetches anything itself. Everything in a container is signed by the
// publisher and checked by each app; this script is trusted with
// nothing. The write key below only stops strangers from replacing the
// texts.
//
// Services used: ContentService, PropertiesService, Utilities. Nothing
// else, and no UrlFetchApp.

var WRITE_KEY_B64 = '__DAAL_WRITE_KEY_B64__';
var PROTOCOL = 'daal-refresh-v2';
var MAX_BLOB = 65536;
// A slot is 11 base64url characters (8 random bytes).
var SLOT_RE = /^[A-Za-z0-9_-]{11}$/;
// Script Properties hold at most 9 KB per value; 3000 UTF-16 units
// are at most 9000 bytes in UTF-8.
var CHUNK = 3000;

// Compare without stopping at the first difference.
function sameText_(given, expected) {
  if (typeof given !== 'string') return false;
  var diff = given.length ^ expected.length;
  for (var i = 0; i < expected.length; i++) {
    diff |= (given.charCodeAt(i) | 0) ^ expected.charCodeAt(i);
  }
  return diff === 0;
}

function text_(s) {
  return ContentService.createTextOutput(s).setMimeType(ContentService.MimeType.TEXT);
}

function answer_(o) {
  return ContentService.createTextOutput(JSON.stringify(o)).setMimeType(ContentService.MimeType.JSON);
}

function hmac_(s) {
  return Utilities.computeHmacSha256Signature(Utilities.newBlob(s).getBytes(),
      Utilities.base64Decode(WRITE_KEY_B64));
}

function hex_(bytes) {
  var out = '';
  for (var i = 0; i < bytes.length; i++) {
    var b = (bytes[i] + 256) % 256;
    out += (b < 16 ? '0' : '') + b.toString(16);
  }
  return out;
}

// A slot's read token: the first 16 bytes of
// HMAC-SHA256(write key, "daal-read-v2\n" + slot), base64url, no padding.
// Only the holder of the write key can make one, so the script keeps no
// list of them.
function readToken_(slot) {
  var mac = hmac_('daal-read-v2\n' + slot).slice(0, 16);
  return Utilities.base64EncodeWebSafe(mac).replace(/=+$/, '');
}

function prefix_(slot) {
  return 's.' + slot + '.';
}

function stored_(all, slot) {
  var p = prefix_(slot);
  var n = parseInt(all[p + 'n'] || '0', 10);
  var parts = [];
  for (var i = 0; i < n; i++) parts.push(all[p + 'c' + i] || '');
  return parts.join('');
}

// ?s=<slot>&k=<read token>
function doGet(e) {
  var q = e && e.parameter ? e.parameter : {};
  var slot = q.s;
  if (typeof slot !== 'string' || !SLOT_RE.test(slot) || !sameText_(q.k, readToken_(slot))) {
    return text_('Nothing here.');
  }
  var blob = stored_(PropertiesService.getScriptProperties().getProperties(), slot);
  return text_(blob || 'Nothing here.');
}

// Body: {"slot": "<slot>", "seq": <integer>, "blob": "<container>",
// "mac": "<64 hex>"}, mac = HMAC-SHA256(write key,
// "daal-refresh-v2\n" + slot + "\n" + decimal seq + "\n" + blob).
// seq only goes up, per slot.
function doPost(e) {
  var req;
  try {
    req = JSON.parse(e.postData.contents);
  } catch (err) {
    return answer_({ ok: false, error: 'malformed' });
  }
  if (!req || typeof req.slot !== 'string' || !SLOT_RE.test(req.slot) ||
      typeof req.blob !== 'string' || typeof req.mac !== 'string' ||
      !Number.isSafeInteger(req.seq) || req.seq < 1) {
    return answer_({ ok: false, error: 'malformed' });
  }
  if (req.blob.length > MAX_BLOB) return answer_({ ok: false, error: 'too_large' });
  var mac = hex_(hmac_(PROTOCOL + '\n' + req.slot + '\n' + String(req.seq) + '\n' + req.blob));
  if (!sameText_(req.mac, mac)) return answer_({ ok: false, error: 'refused' });

  var props = PropertiesService.getScriptProperties();
  var all = props.getProperties();
  var p = prefix_(req.slot);
  var seq = parseInt(all[p + 'q'] || '0', 10);
  if (req.seq < seq) return answer_({ ok: false, error: 'stale', seq: seq });
  if (req.seq === seq) {
    // The same update again is fine; a different one at the same
    // number is not.
    if (stored_(all, req.slot) === req.blob) return answer_({ ok: true, seq: seq });
    return answer_({ ok: false, error: 'stale', seq: seq });
  }
  var next = {};
  next[p + 'q'] = String(req.seq);
  var n = 0;
  for (var at = 0; at < req.blob.length; at += CHUNK) {
    next[p + 'c' + n] = req.blob.substring(at, at + CHUNK);
    n++;
  }
  next[p + 'n'] = String(n);
  try {
    // One call, so a reader sees the old text or the new one. Other
    // slots are left as they are.
    props.setProperties(next, false);
  } catch (err) {
    // The account's property store is full (about 500 KB in all).
    return answer_({ ok: false, error: 'full' });
  }
  var old = parseInt(all[p + 'n'] || '0', 10);
  for (var i = n; i < old; i++) props.deleteProperty(p + 'c' + i);
  return answer_({ ok: true, seq: req.seq });
}
