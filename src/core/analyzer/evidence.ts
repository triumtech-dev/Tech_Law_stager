/**
 * קטע ראיה לממצא. חלון קצר סביב ההתאמה, מתוך קובץ שכבר עבר `maskSecrets` על כולו.
 * ⛔ שלוש שכבות, כי תבנית לא תמיד מכירה את הסוד שיושב באותה שורה (Gate A, 5.11.2026):
 *   1. הקובץ כולו מוסתר לפני כל גלאי (`analyze.ts`).
 *   2. כאן: הסתרה חוזרת של החלון, ומחרוזת ארוכה שמערבבת אותיות וספרות (כמו מפתח) מוסתרת גם בלי תבנית.
 *   3. החלון נחתך בגבול מילה, כדי שחצי של סוד לא יישאר גלוי בקצה.
 */

import { EVIDENCE_MAX } from '../constants'

import { REDACTED, redactSecrets } from './secrets'

export interface LineLocator {
  /** מספר השורה (מ-1) של אינדקס בטקסט. */
  lineAt(_index: number): number
  /** אינדקס תחילת השורה בטקסט. */
  lineStart(_line: number): number
  /** תוכן השורה (בלי תו סוף השורה). */
  lineText(_line: number): string
}

export function makeLocator(text: string): LineLocator {
  const starts = [0]
  for (let i = 0; i < text.length; i += 1) if (text.charCodeAt(i) === 10) starts.push(i + 1)
  return {
    lineAt(index) {
      let lo = 0
      let hi = starts.length - 1
      while (lo < hi) {
        const mid = (lo + hi + 1) >> 1
        if ((starts[mid] ?? 0) <= index) lo = mid
        else hi = mid - 1
      }
      return lo + 1
    },
    lineStart(line) {
      return starts[line - 1] ?? text.length
    },
    lineText(line) {
      const start = starts[line - 1] ?? text.length
      const next = starts[line]
      return text.slice(start, next === undefined ? text.length : next - 1).replace(/\r$/, '')
    },
  }
}

/** חלקי כתובת שנושאים לעיתים קרובות טוקנים (שאילתה, fragment) מוחלפים ב-`…`. גבולות קבועים, בלי backtracking. */
const URL_TAIL = /(\b[a-z][a-z0-9+.-]{0,20}:\/\/[^\s"'`?#]{1,300})[?#][^\s"'`]{0,2000}/gi
/** מחרוזת של 20 תווים ומעלה מאלפבית של מפתחות. מוסתרת כשיש בה גם אות וגם ספרה. */
const TOKEN_LIKE = /[A-Za-z0-9+/=_~-]{20,1000}/g

function maskHighEntropy(text: string): string {
  return text.replace(TOKEN_LIKE, (t) => (/[0-9]/.test(t) && /[A-Za-z]/.test(t) ? REDACTED : t))
}

/** ראיה לטקסט קצר (שם תלות, מארח). */
export function evidenceFor(text: string): string {
  const clean = maskHighEntropy(redactSecrets(text.slice(0, EVIDENCE_MAX * 3)).replace(URL_TAIL, '$1?…')).trim().replace(/\s+/g, ' ')
  return clean.length <= EVIDENCE_MAX ? clean : `${clean.slice(0, EVIDENCE_MAX - 1)}…`
}

/**
 * ראיה לשורה סביב העמודה של ההתאמה. ⭐ החלון חסום, ולכן העלות לא תלויה באורך השורה (Gate A: שורה של 48KB
 * עם אלפי ממצאים לקחה שניות, כי כל ממצא הסתיר את כל השורה מחדש).
 */
export function evidenceAt(lineText: string, column: number): string {
  const start = Math.max(0, column - Math.floor(EVIDENCE_MAX / 2))
  const end = Math.min(lineText.length, start + EVIDENCE_MAX * 2)
  let window = lineText.slice(start, end)
  if (start > 0) window = `…${window.replace(/^\S{0,1000}\s?/, '')}`
  if (end < lineText.length) window = `${window.replace(/\s?\S{0,1000}$/, '')}…`
  return evidenceFor(window)
}

/** שורה שהיא הערה בלבד. ממצאים בהערה מדולגים (חוץ מסודות: סוד בהערה דולף בדיוק כמו בקוד). */
export function isCommentLine(lineText: string): boolean {
  return /^\s*(?:\/\/|\/\*|\*|#(?!!)|<!--)/.test(lineText)
}
