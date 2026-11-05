/**
 * מארחים חיצוניים שהקוד פונה אליהם או טוען מהם (כתובות `https://` במחרוזות).
 * הממצא הוא רשימת מארחים לטיוטת הפרטיות ולנספח הטכני. סיווג (תשלום, CDN, גופנים) רק למארח מוכר; השאר `unknown`.
 * ⛔ מארחי תיעוד וסכמות (`w3.org`, `schema.org`) ומארחים מקומיים אינם ממצא.
 */

import { evidenceFor, isCommentLine, makeLocator } from './evidence'
import { extensionOf } from './files'
import { CODE_EXTENSIONS } from './rules'
import type { Finding, ProcessType, RepoFile } from './types'

const URL_IN_STRING = /["'`(]\s*(https?:)?\/\/([a-z0-9-]+(?:\.[a-z0-9-]+)+)(?::\d+)?[/"'`?#)]/gi

const IGNORED = /(?:^|\.)(?:w3\.org|schema\.org|example\.(?:com|org|net)|localhost|xmlns\.com|purl\.org|ogp\.me|json-schema\.org|mozilla\.org|developer\.mozilla\.org|reactjs\.org|react\.dev|nextjs\.org|typescriptlang\.org|npmjs\.com|github\.com|githubusercontent\.com|stackoverflow\.com|wikipedia\.org)$|^(?:127\.0\.0\.1|0\.0\.0\.0)$/i

interface HostClass {
  readonly test: RegExp
  readonly category: string
  readonly processType: ProcessType
}

/** סיווג למארחים מוכרים בלבד. תשלום ישראלי מזוהה לפי שם הספק במארח, לא לפי כתובת מנוחשת. */
const CLASSES: readonly HostClass[] = [
  { test: /(?:^|\.)(?:stripe\.com|paypal\.com|paypalobjects\.com|braintreegateway\.com)$|cardcom|payplus|tranzila|meshulam|grow-il|hyp\.co\.il|isracard|pelecard|icredit/i, category: 'payments', processType: 'payments' },
  { test: /(?:^|\.)(?:fonts\.googleapis\.com|fonts\.gstatic\.com|use\.typekit\.net)$/i, category: 'fonts', processType: 'third_party' },
  { test: /(?:^|\.)(?:cdn\.jsdelivr\.net|unpkg\.com|cdnjs\.cloudflare\.com|code\.jquery\.com)$/i, category: 'cdn', processType: 'third_party' },
  { test: /(?:^|\.)(?:youtube\.com|youtube-nocookie\.com|vimeo\.com|player\.vimeo\.com)$/i, category: 'video_embed', processType: 'third_party' },
  { test: /(?:^|\.)(?:maps\.googleapis\.com|maps\.google\.com|api\.mapbox\.com|tile\.openstreetmap\.org)$/i, category: 'maps', processType: 'third_party' },
  { test: /(?:^|\.)(?:recaptcha\.net|challenges\.cloudflare\.com|hcaptcha\.com|google\.com)$/i, category: 'captcha_or_google', processType: 'third_party' },
  { test: /(?:^|\.)(?:api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|aiplatform\.googleapis\.com)$/i, category: 'ai_api', processType: 'third_party' },
  { test: /(?:^|\.)(?:firebaseio\.com|firestore\.googleapis\.com|firebasestorage\.googleapis\.com|supabase\.co|amazonaws\.com|cloudinary\.com)$/i, category: 'storage_backend', processType: 'third_party' },
]

/** תווית של 12 תווים ומעלה עם אותיות וספרות מוחלפת ב-`*`. */
export function maskHostLabels(host: string): string {
  return host
    .split('.')
    .map((label) => (label.length >= 12 && /[0-9]/.test(label) && /[a-z]/i.test(label) ? '*' : label))
    .join('.')
}

export function classifyHost(host: string): { category: string; processType: ProcessType } {
  const hit = CLASSES.find((c) => c.test.test(host))
  return hit === undefined ? { category: 'unknown', processType: 'third_party' } : { category: hit.category, processType: hit.processType }
}

/** ממצא `host:<category>:<host>` למופע הראשון של כל מארח בקובץ. */
export function hostFindings(file: RepoFile): Finding[] {
  const ext = extensionOf(file.path)
  if (!(CODE_EXTENSIONS as readonly string[]).includes(ext) && ext !== 'json') return []
  const locator = makeLocator(file.text)
  const seen = new Set<string>()
  const out: Finding[] = []
  URL_IN_STRING.lastIndex = 0
  for (const m of file.text.matchAll(URL_IN_STRING)) {
    const host = (m[2] ?? '').toLowerCase()
    if (host === '' || IGNORED.test(host) || seen.has(host) || m.index === undefined) continue
    const line = locator.lineAt(m.index)
    if (isCommentLine(locator.lineText(line))) continue
    seen.add(host)
    const { category, processType } = classifyHost(host)
    // ⛔ הראיה היא המארח בלבד: נתיב ושאילתה של כתובת נושאים טוקנים (webhook, `?key=`), גם כשאין להם תבנית מוכרת.
    // ⛔ ובמארח עצמו, תווית ארוכה שמערבבת אותיות וספרות היא לרוב מזהה סודי (`eo1a2b….m.pipedream.net`), ומוחלפת ב-`*`.
    const shown = maskHostLabels(host)
    out.push({ kind: `host:${category}:${shown}`, processType, path: file.path, line, evidence: evidenceFor(shown), confidence: category === 'unknown' ? 'low' : 'medium' })
  }
  return out
}
