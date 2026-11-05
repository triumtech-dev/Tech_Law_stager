/**
 * מנוע הכללים של המנתח. כלל הוא תבנית שמזהה סימן בקוד, וממופה לסוג תהליך (אפיון סעיף 5).
 * הכללים עצמם בקבצי `rules-*.ts`. כלל שמתאים בשורת הערה מדולג.
 * ⛔ כלל מזהה סימן, לא קובע הפרה. "יש תיבה מסומנת מראש" הוא ממצא; "זו הפרה" הוא שיקול של עורך הדין.
 */

import { evidenceAt, isCommentLine, makeLocator } from './evidence'
import { extensionOf } from './files'
import type { Confidence, Finding, ProcessType, RepoFile } from './types'

export interface Rule {
  readonly kind: string
  readonly processType: ProcessType
  /** חייבת להיות `g`. */
  readonly pattern: RegExp
  readonly confidence: Confidence
  /** סיומות שהכלל רץ עליהן. חסר: כל קובץ שנקרא. */
  readonly extensions?: readonly string[]
  /**
   * בדיקה נוספת על טקסט ההתאמה. ⭐ כך תבנית התג נשארת ליניארית (`<input\b[^>]{0,1000}>`), והתנאים על
   * התכונות נבדקים בקוד ולא בשני כמתים סמוכים שגורמים ל-backtracking קובי (Gate A, ReDoS).
   */
  readonly accept?: (_match: string) => boolean
}

/**
 * גוף תגית פתיחה, עד 600 תווים, וה-`>` אופציונלי. כל כלל על תגיות נבנה מזה ולא מ-`[^>]*` חופשי.
 * ⭐ בלי `>` חובה ההתאמה תמיד מצליחה, ולכן אין backtracking, והחיפוש ממשיך אחרי סוף ההתאמה: עבודה ליניארית
 * גם על אלפי תגיות שלא נסגרות (Gate A, סבב 3: 990KB של `<input` לקחו 5.6 שניות).
 */
export const TAG_BODY = '[^>]{0,600}>?'

/** סיומות של קוד ממשק, לכללים על טפסים, כפתורים ותצוגה. */
export const UI_EXTENSIONS = ['js', 'jsx', 'ts', 'tsx', 'mjs', 'vue', 'svelte', 'astro', 'html', 'htm', 'php'] as const
/** כל סיומות הקוד (בלי קבצי תיעוד ותצורה). */
export const CODE_EXTENSIONS = [...UI_EXTENSIONS, 'cjs', 'mts', 'cts', 'py', 'rb', 'go', 'java', 'kt', 'swift', 'dart', 'cs'] as const

function assertGlobal(rule: Rule): void {
  if (!rule.pattern.flags.includes('g')) throw new Error(`rule ${rule.kind} pattern must be global`)
}

/** מריץ רשימת כללים על קובץ אחד. התאמה אחת לכל כלל בכל שורה. */
export function runRules(file: RepoFile, rules: readonly Rule[]): Finding[] {
  const ext = extensionOf(file.path)
  const locator = makeLocator(file.text)
  const out: Finding[] = []
  for (const rule of rules) {
    assertGlobal(rule)
    if (rule.extensions !== undefined && !rule.extensions.includes(ext)) continue
    const seenLines = new Set<number>()
    rule.pattern.lastIndex = 0
    for (const m of file.text.matchAll(rule.pattern)) {
      if (m.index === undefined) continue
      if (rule.accept !== undefined && !rule.accept(m[0])) continue
      const line = locator.lineAt(m.index)
      if (seenLines.has(line)) continue
      seenLines.add(line)
      const text = locator.lineText(line)
      if (isCommentLine(text)) continue
      const evidence = evidenceAt(text, m.index - locator.lineStart(line))
      out.push({ kind: rule.kind, processType: rule.processType, path: file.path, line, evidence, confidence: rule.confidence })
    }
  }
  return out
}
