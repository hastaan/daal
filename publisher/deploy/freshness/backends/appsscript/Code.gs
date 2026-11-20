// Daal update channel (specs/relaypack-v1.md, "Mirror provider
// appsscript"; docs/optional-addons-plan.md §3).
//
// It keeps one small text, a daal-refresh-v1 container, and hands it to
// whoever asks with the right k. It never fetches anything itself.
// Everything in the container is signed by the publisher and checked by
// each app; this script is trusted with nothing. The write key below
// only stops strangers from replacing the text.
//
// Services used: ContentService, PropertiesService, Utilities. Nothing
// else, and no UrlFetchApp.

var WRITE_KEY_B64 = '__DAAL_WRITE_KEY_B64__';
var PATH_TOKEN = '__DAAL_PATH_TOKEN__';
var KIND = 'daal-refresh-v1';
var MAX_BLOB = 65536;
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

function stored_(all) {
  var n = parseInt(all.n || '0', 10);
  var parts = [];
  for (var i = 0; i < n; i++) parts.push(all['c' + i] || '');
  return parts.join('');
}

function hex_(bytes) {
  var out = '';
  for (var i = 0; i < bytes.length; i++) {
    var b = (bytes[i] + 256) % 256;
    out += (b < 16 ? '0' : '') + b.toString(16);
  }
  return out;
}

function doGet(e) {
  var k = e && e.parameter ? e.parameter.k : '';
  if (!sameText_(k, PATH_TOKEN)) return text_('Nothing here.');
  var blob = stored_(PropertiesService.getScriptProperties().getProperties());
  return text_(blob || JSON.stringify({ kind: KIND }));
}

// Body: {"seq": <integer>, "blob": "<container>", "mac": "<64 hex>"},
// mac = HMAC-SHA256(write key, decimal seq + "\n" + blob).
function doPost(e) {
  var req;
  try {
    req = JSON.parse(e.postData.contents);
  } catch (err) {
    return answer_({ ok: false, error: 'malformed' });
  }
  if (!req || typeof req.blob !== 'string' || typeof req.mac !== 'string' ||
      !Number.isSafeInteger(req.seq) || req.seq < 1) {
    return answer_({ ok: false, error: 'malformed' });
  }
  if (req.blob.length > MAX_BLOB) return answer_({ ok: false, error: 'too_large' });
  var msg = Utilities.newBlob(String(req.seq) + '\n' + req.blob).getBytes();
  var mac = hex_(Utilities.computeHmacSha256Signature(msg, Utilities.base64Decode(WRITE_KEY_B64)));
  if (!sameText_(req.mac, mac)) return answer_({ ok: false, error: 'refused' });

  var props = PropertiesService.getScriptProperties();
  var all = props.getProperties();
  var seq = parseInt(all.seq || '0', 10);
  if (req.seq < seq) return answer_({ ok: false, error: 'stale', seq: seq });
  if (req.seq === seq) {
    // The same update again is fine; a different one at the same
    // number is not.
    if (stored_(all) === req.blob) return answer_({ ok: true, seq: seq });
    return answer_({ ok: false, error: 'stale', seq: seq });
  }
  var next = { seq: String(req.seq) };
  var n = 0;
  for (var at = 0; at < req.blob.length; at += CHUNK) {
    next['c' + n] = req.blob.substring(at, at + CHUNK);
    n++;
  }
  next.n = String(n);
  props.setProperties(next, true);
  return answer_({ ok: true, seq: req.seq });
}
