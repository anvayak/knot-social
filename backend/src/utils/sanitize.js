// Second line of defence against stored XSS: even if something slips past the
// payload scanner, user text is cleaned before it is saved.
export function sanitizeText(input) {
  let t = String(input).normalize('NFC');
  // control characters, zero-width and bidi-override characters (used to spoof text)
  t = t.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u200B-\u200F\u202A-\u202E\u2066-\u2069]/g, '');
  // strip HTML tags until none are left (handles <scr<script>ipt>). Only things that
  // look like tags are removed, so "1 < 2" and "3 > 2" survive.
  let prev;
  do {
    prev = t;
    t = t.replace(/<\/?[a-zA-Z!?][^>]*>/g, '');
  } while (t !== prev);
  // a "<" that still starts a tag name (unclosed tag) loses the "<"
  t = t.replace(/<(?=[a-zA-Z\/!?])/g, '');
  t = t.replace(/\n{3,}/g, '\n\n');
  return t.trim();
}