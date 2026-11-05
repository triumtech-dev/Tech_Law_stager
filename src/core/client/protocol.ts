/**
 * הפרוטוקול בין חבילת הלקוח לשרת (R4b ממש את הצד השני). מבנים בלבד.
 * ⛔ הנתיב של הלקוח לשרת עובר רק דרך מעטפת אטומה (`seal.ts`). אין שדות גלויים מחוץ למעטפת: השרת פותח אותה
 * ברגע הקליטה כדי לאמת ולהוציא את פרטי הקשר לפנייה (סעיף 5.1.6), ושומר אותה אטומה עד שעורך הדין פותח.
 * אסימון OIDC: בהתחלה בקהל `lawstager`, ובשליחה בקהל `lawstager:<nonce>` (קשור למעטפת).
 */

import type { SealedEnvelope } from './seal'

/** עורך דין שלא נקבע בקישור: הפנייה מגיעה למאגר (סעיף 5.2). */
export const POOL_LAWYER_ID = 'pool'
/** כתובת הפונקציות. ערך שלא הוכרע (שם הדומיין הציבורי ייקבע בהקמת הריפו הפומבי). */
export const LAWSTAGER_ENDPOINT_INVENTED = 'https://europe-west1-israelaw.cloudfunctions.net'
export const BEGIN_FUNCTION = 'beginClientScan'
export const SUBMIT_FUNCTION = 'submitClientScan'

export interface BeginRequest {
  readonly lawyerId: string
  /** אסימון OIDC של GitHub Actions. חסר במסלול המקומי, והסריקה מסומנת "לא מאומתת". */
  readonly oidcToken?: string
}

export interface BeginResponse {
  readonly nonce: string
  /** המפתח הציבורי של השרת להצפנת המעטפת (PEM). */
  readonly serverPublicKeyPem: string
  /** גרסת ההסכמה שהשרת מצפה לה. אם שונה מזו שבחבילה, השליחה נעצרת. */
  readonly consentVersion: string
}

export interface SubmitRequest {
  readonly envelope: SealedEnvelope
  /** מפתח ייחודי לבקשה: לחיצה כפולה לא יוצרת שתי סריקות. */
  readonly requestId: string
  readonly oidcToken?: string
}

export interface SubmitResponse {
  readonly scanId: string
}
