/**
 * זיהוי סודות בקוד הלקוח והסתרתם.
 * ⛔ ההסתרה נעשית על הקובץ כולו (`maskSecrets`), לפני שאף גלאי אחר רץ, כי סוד יכול להתפרס על כמה שורות
 * (שם בשורה אחת וערך בבאה, מפתח PEM). הסתרה של שורה בודדת לא מספיקה (Gate A, 5.11.2026).
 * ⛔ התאמות חופפות מתמזגות לטווח אחד, וערך שנראה כמו placeholder מוסתר תמיד; placeholder רק לא נחשב ממצא.
 * הממצא אומר רק "נמצא סוד מסוג X בקובץ Y בשורה Z" (אפיון סעיף 8).
 */

export const REDACTED = '[REDACTED]'

interface SecretPattern {
  readonly id: string
  readonly pattern: RegExp
  /** מספר הקבוצה שהיא הערך הסודי. 0: כל ההתאמה. */
  readonly group: number
}

/**
 * הספציפיות קודם. תבנית כללית שחופפת לספציפית מתמזגת איתה.
 * ⛔ כל כמת חסום (`{n,1000}` ולא `{n,}`): `\b` אחרי כל `-` הפך כמת פתוח לריבועי (Gate A, `eyJ-` חוזר).
 */
const PATTERNS: readonly SecretPattern[] = [
  // גוף ה-PEM הוא base64, רווחים ו-`\n` מוברח בלבד. ⛔ לא `[\s\S]*?…|$`: כותרת PEM במחרוזת רגילה הסתירה את כל שאר הקובץ.
  { id: 'private_key', pattern: /-----BEGIN (?:[A-Z0-9]{1,20} ){0,4}PRIVATE KEY(?: BLOCK)?-----(?:[A-Za-z0-9+/= \t\r\n]|\\n|\\r){0,10000}(?:-----END (?:[A-Z0-9]{1,20} ){0,4}PRIVATE KEY(?: BLOCK)?-----)?/g, group: 0 },
  { id: 'aws_access_key', pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, group: 0 },
  { id: 'aws_secret_key', pattern: /aws_?secret_?(?:access_?)?key["']?\s{0,5}(?:[:=]|\s)\s{0,5}["']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])/gi, group: 1 },
  { id: 'google_api_key', pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g, group: 0 },
  { id: 'google_oauth_secret', pattern: /\bGOCSPX-[A-Za-z0-9_-]{20,200}/g, group: 0 },
  { id: 'github_token', pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{40,255})/g, group: 0 },
  { id: 'npm_token', pattern: /\bnpm_[A-Za-z0-9]{36,100}|_authToken\s{0,3}=\s{0,3}(\S{8,500})/g, group: 0 },
  { id: 'stripe_key', pattern: /\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9_-]{16,500}|\bwhsec_[A-Za-z0-9]{16,500}/g, group: 0 },
  { id: 'ai_api_key', pattern: /\bsk-(?:proj-|ant-[a-z0-9]{1,20}-)?[A-Za-z0-9_-]{20,500}/g, group: 0 },
  { id: 'slack_token', pattern: /\bxox[abprs]-[A-Za-z0-9-]{10,500}/g, group: 0 },
  { id: 'webhook_url', pattern: /hooks\.slack\.com\/services\/[A-Za-z0-9/_-]{20,500}|discord(?:app)?\.com\/api\/webhooks\/[0-9]{1,30}\/[A-Za-z0-9_-]{20,500}/g, group: 0 },
  { id: 'telegram_bot_token', pattern: /\b(?:bot)?[0-9]{6,12}:[A-Za-z0-9_-]{30,200}/g, group: 0 },
  { id: 'jwt', pattern: /\beyJ[A-Za-z0-9_-]{8,300}\.eyJ[A-Za-z0-9_-]{8,4000}\.[A-Za-z0-9_-]{8,2000}/g, group: 0 },
  { id: 'http_auth_header', pattern: /\b(?:Bearer|Basic|Token)\s{1,5}([A-Za-z0-9._~+/=-]{12,2000})/g, group: 1 },
  // סכמה אופציונלית (כתובת `//user:pass@host`). הסיסמה עד ה-`@` האחרון לפני המארח, באורך כלשהו עד סוף השורה.
  { id: 'url_credentials', pattern: /(?:\b[a-z][a-z0-9+.-]{0,20}:)?\/\/[^\s:/'"`@]{1,200}:([^\s'"`]{1,2000})@[^\s@/'"`]{1,200}/gi, group: 1 },
  { id: 'url_query_secret', pattern: /[?&\s"'](?:key|api_key|apikey|token|access_token|refresh_token|auth|secret|client_secret|sig|signature|password|pass|pwd)=([^&\s"'`#]{6,2000})/gi, group: 1 },
  {
    id: 'named_secret',
    pattern: /\b[A-Za-z0-9_]{0,40}(?:password|passwd|passphrase|pass|pwd|secret|token|credentials?|api[_-]?key|apikey|private[_-]?key)[A-Za-z0-9_]{0,40}["']?\s{0,10}[:=]\s{0,10}["'`]((?:[^"'`\\\n]|\\.){8,500})["'`]/gi,
    group: 1,
  },
  // `pw` כמפתח שלם (קצר מכדי להיכלל ב-named_secret בלי התאמות שווא).
  { id: 'named_secret', pattern: /\b(?:pw|pwd)["']?\s{0,10}[:=]\s{0,10}["'`]((?:[^"'`\\\n]|\\.){4,500})["'`]/gi, group: 1 },
  // סיסמה לפי מיקום: `smtp.login('user', 'pw')`, `connect(...)`, וזוג `auth=('user', 'pw')` של requests (Gate A, סבב 3).
  { id: 'positional_password', pattern: /\.(?:login|connect|auth(?:enticate)?)\(\s{0,5}['"][^'"\n]{1,200}['"]\s{0,5},\s{0,5}['"]([^'"\n]{4,500})['"]/g, group: 1 },
  { id: 'positional_password', pattern: /\bauth\s{0,3}=\s{0,3}\(\s{0,3}['"][^'"\n]{1,200}['"]\s{0,3},\s{0,3}['"]([^'"\n]{4,500})['"]/g, group: 1 },
  // צורת קובצי תצורה (env, sh, ini, yaml): `NAME=value` בלי מרכאות.
  { id: 'config_secret', pattern: /(?:^|[\s;])(?:export\s{1,3})?[A-Za-z0-9_.-]{0,40}(?:SECRET|PASSWORD|PASSWD|TOKEN|API_?KEY|PRIVATE_?KEY|PASS|PWD)[A-Za-z0-9_.-]{0,40}\s{0,3}[=:]\s{0,3}([^\s"'`$({][^\s"'`]{7,500})/gim, group: 1 },
]

/** ערכים שנראים כמו placeholder. הם מוסתרים, אבל אינם ממצא. בלי `test` ו-`example` כקידומת: סיסמאות אמיתיות מתחילות כך. */
const PLACEHOLDER = /^(?:x{4,}|\*{4,}|\.{4,}|changeme|change_me|your[_-](?:api[_-]?key|secret|password|token)(?:[_-]here)?|<[^>]*>|\$\{[^}]*\}|process\.env\.[A-Z0-9_]+|placeholder)$/i

const TOKEN_CHAR = /[A-Za-z0-9_+/=~-]/
const MAX_SPAN = 50_000

export interface SecretHit {
  readonly id: string
  /** אינדקס תחילת הטווח בטקסט. */
  readonly index: number
  readonly length: number
  /** ערך שנראה כמו placeholder: מוסתר, ולא מדווח כממצא. */
  readonly placeholder: boolean
}

function rawHits(text: string): SecretHit[] {
  const hits: SecretHit[] = []
  for (const { id, pattern, group } of PATTERNS) {
    // הדגל `d` נותן את מיקום הקבוצה עצמה. ⛔ לא `indexOf` על הערך: ערך קצר יכול להופיע גם במארח ואז מוסתר הדבר הלא נכון.
    const withIndices = new RegExp(pattern.source, pattern.flags.includes('d') ? pattern.flags : `${pattern.flags}d`)
    for (const m of text.matchAll(withIndices)) {
      const value = m[group]
      const span = m.indices?.[group]
      if (value === undefined || value === '' || span === undefined) continue
      // הארכה ליניארית: כמת חסום לא משאיר זנב גלוי של טוקן ארוך מהתקרה (Gate A, סבב 3).
      let end = span[1]
      while (end < text.length && end - span[0] < MAX_SPAN && TOKEN_CHAR.test(text[end] ?? '')) end += 1
      hits.push({ id, index: span[0], length: end - span[0], placeholder: id === 'named_secret' && PLACEHOLDER.test(value) })
    }
  }
  return hits
}

/** טווחים ממוזגים: חפיפה או נגיעה מתאחדות לטווח אחד. הסוג נלקח מהטווח שהתחיל ראשון. */
export function findSecrets(text: string): SecretHit[] {
  const sorted = rawHits(text).sort((a, b) => a.index - b.index || b.length - a.length)
  const merged: SecretHit[] = []
  for (const hit of sorted) {
    const last = merged.at(-1)
    if (last !== undefined && hit.index <= last.index + last.length) {
      const end = Math.max(last.index + last.length, hit.index + hit.length)
      merged[merged.length - 1] = { ...last, length: end - last.index, placeholder: last.placeholder && hit.placeholder }
    } else {
      merged.push(hit)
    }
  }
  return merged
}

/**
 * הטקסט, כשכל טווח סודי מוחלף ב-`[REDACTED]`. ⭐ תווי סוף שורה בתוך הטווח נשמרים, כדי שמספרי השורות
 * בקובץ המוסתר יהיו זהים למקור, וכל גלאי יוכל לרוץ על הקובץ המוסתר בלבד.
 */
export function maskSecrets(text: string, hits: readonly SecretHit[] = findSecrets(text)): string {
  if (hits.length === 0) return text
  let out = ''
  let cursor = 0
  for (const hit of hits) {
    const segment = text.slice(hit.index, hit.index + hit.length)
    out += text.slice(cursor, hit.index) + segment.split('\n').map((part) => (part.replace(/\r$/, '') === '' ? part : REDACTED)).join('\n')
    cursor = hit.index + hit.length
  }
  return out + text.slice(cursor)
}

/** שם נוח לקריאה על מחרוזת קצרה (ראיה, קלט למודל). */
export function redactSecrets(text: string): string {
  return maskSecrets(text)
}
