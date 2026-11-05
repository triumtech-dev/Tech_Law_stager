/**
 * מה הלקוח שולח בשלב 2 (אפיון v0.2 סעיפים 5.1, 5.1א, 7). מודול טהור: ולידציה ובנייה בלבד.
 * ⛔ ההסתייגות של הלקוח אינה מוחקת ממצא (סעיף 5.1א.2): הממצאים נשמרים כפי שהקוד הפיק אותם,
 * והאישורים וההערות נשמרים לצדם. מלל חופשי הוא הצהרת לקוח, מסומן "לא אומת", ואינו מתערבב בממצאים.
 */

import type { ClientFindingsFile } from '../client-findings'

import { CLIENT_SCAN_CONSENT_VERSION, HOOK_CONSENT_VERSION } from './consent'
import type { ChangeReport } from './diff'
import { isValidChangeReport, isValidFindingsFile } from './findings-validate'

export const DISAGREE_NOTE_MAX_INVENTED = 500
export const DECLARATION_MAX_INVENTED = 4000
export const FIELD_MAX_INVENTED = 200

export type Verdict = 'agree' | 'disagree'
/** `verified` רק כשהאסימון של GitHub Actions מצורף (R4b). בלעדיו המסלול `local` ומסומן "לא מאומת". */
export type RunMode = 'github-actions' | 'local'

export interface ProcessReview {
  readonly kind: string
  readonly verdict: Verdict
  /** חובה כש-`verdict` הוא `disagree`. */
  readonly note?: string
}

export interface ClientDetails {
  readonly systemName: string
  readonly siteUrl: string
  readonly contactName: string
  readonly contactEmail: string
  readonly contactPhone?: string
}

/** הצהרת הלקוח: תמיד "לא אומת". */
export interface ClientDeclaration {
  readonly text: string
  readonly status: 'unverified'
}

export interface ClientSubmission {
  readonly findings: ClientFindingsFile
  readonly reviews: readonly ProcessReview[]
  readonly declaration: ClientDeclaration
  readonly details: ClientDetails
  readonly consentVersion: string
  readonly runMode: RunMode
  /** קיים רק בדוח שינויים של הוק (R5c). חסר = סריקה רגילה. */
  readonly hook?: ChangeReport
  /** גרסת ההסכמה החד-פעמית להוק. נאכפת בשרת ונשמרת כעדות (P-5). */
  readonly hookConsentVersion?: string
}

export interface SubmissionInput {
  readonly findings: ClientFindingsFile
  readonly reviews: readonly ProcessReview[]
  readonly declarationText: string
  readonly details: ClientDetails
  readonly consentGiven: boolean
  readonly runMode: RunMode
  /**
   * דוח שינויים של הוק. ההסכמה (`consentGiven`) היא ההסכמה החד-פעמית לשליחה אוטומטית. תהליכים חדשים לא נסקרו על ידי הלקוח,
   * ולכן בהוק אין חובה לסקור את כולם, אך סקירה של תהליך שאינו בקובץ עדיין נדחית.
   */
  readonly hook?: ChangeReport
}

export type SubmissionResult = { ok: true; submission: ClientSubmission } | { ok: false; errors: string[] }

// ⛔ חלק מקומי קשיח (Gate B): בלי פסיק, נקודה-פסיק, סוגריים משולשים או מרכאות, שמאפשרים לפרש את השדה כרשימת נמענים או כשם תצוגה.
const EMAIL = /^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,190}\.[A-Za-z]{2,}$/
const PHONE = /^[0-9+\-\s()]{7,20}$/

function clean(value: string | undefined): string {
  return (value ?? '').replace(/\r\n/g, '\n').trim()
}

function validUrl(raw: string): boolean {
  try {
    const url = new URL(raw)
    return url.protocol === 'https:' || url.protocol === 'http:'
  } catch {
    return false
  }
}

/** בודק ובונה את מה שנשלח. מחזיר רשימת שגיאות בעברית, או את הגוף המוכן. */
export function buildSubmission(input: SubmissionInput): SubmissionResult {
  const errors: string[] = []
  if (!isValidFindingsFile(input.findings)) return { ok: false, errors: ['קובץ הממצאים אינו תקין'] }
  const { details } = input
  const name = clean(details.systemName)
  const url = clean(details.siteUrl)
  const contactName = clean(details.contactName)
  const email = clean(details.contactEmail)
  const phone = clean(details.contactPhone)

  if (!name) errors.push('חסר שם המערכת')
  if (!validUrl(url)) errors.push('כתובת האתר אינה תקינה (נדרשת כתובת שמתחילה ב-https://)')
  if (!contactName) errors.push('חסר שם איש הקשר')
  if (!EMAIL.test(email)) errors.push('כתובת המייל אינה תקינה')
  if (phone && !PHONE.test(phone)) errors.push('מספר הטלפון אינו תקין')
  for (const value of [name, url, contactName, email, phone]) {
    if (value.length > FIELD_MAX_INVENTED) errors.push('אחד השדות ארוך מדי')
  }

  const known = new Set(input.findings.processes.map((p) => p.kind))
  const seen = new Set<string>()
  const reviews: ProcessReview[] = []
  for (const review of input.reviews) {
    if (!known.has(review.kind)) {
      errors.push('אישור לתהליך שלא נמצא בקובץ הממצאים')
      continue
    }
    if (seen.has(review.kind)) {
      errors.push('אותו תהליך סומן פעמיים')
      continue
    }
    seen.add(review.kind)
    const note = clean(review.note)
    if (review.verdict === 'disagree' && !note) errors.push('תהליך שסומן "לא מסכים" דורש הסבר קצר')
    if (note.length > DISAGREE_NOTE_MAX_INVENTED) errors.push('הסבר ארוך מדי')
    reviews.push(review.verdict === 'disagree' ? { kind: review.kind, verdict: 'disagree', note } : { kind: review.kind, verdict: 'agree' })
  }
  if (input.hook === undefined && seen.size !== known.size) errors.push('לא כל התהליכים סומנו: חובה לאשר או לחלוק על כל אחד')
  if (input.hook !== undefined) {
    const h = input.hook
    // ⛔ דוח שינויים ריק, או שאינו מתאים לממצאים, לא עוקף את חובת הסקירה (Gate A): מה שנוסף חייב להיות בקובץ, ומה שהוסר חייב להיעדר ממנו.
    const consistent =
      isValidChangeReport(h) && h.added.length + h.removed.length > 0 && h.added.every((k) => known.has(k)) && h.removed.every((k) => !known.has(k)) && new Set(h.added).size === h.added.length
    if (!consistent) errors.push('דוח השינויים אינו תקין')
  }

  const declarationText = clean(input.declarationText)
  if (declarationText.length > DECLARATION_MAX_INVENTED) errors.push('ההצהרה החופשית ארוכה מדי')
  if (!input.consentGiven) errors.push('חובה לסמן הסכמה מדעת לפני שליחה')

  if (errors.length > 0) return { ok: false, errors }
  return {
    ok: true,
    submission: {
      findings: input.findings,
      reviews,
      declaration: { text: declarationText, status: 'unverified' },
      details: { systemName: name, siteUrl: url, contactName, contactEmail: email, ...(phone ? { contactPhone: phone } : {}) },
      consentVersion: CLIENT_SCAN_CONSENT_VERSION,
      runMode: input.runMode,
      ...(input.hook ? { hook: { added: input.hook.added, removed: input.hook.removed, baselineHash: input.hook.baselineHash }, hookConsentVersion: HOOK_CONSENT_VERSION } : {}),
    },
  }
}
