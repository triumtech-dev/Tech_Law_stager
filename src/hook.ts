/**
 * סטאג'ר משפטי, חבילת הסריקה: הוק (R5c). רץ אחרי שינוי בקוד, משווה לבסיס שהלקוח אישר, ושולח דוח שינויים רק כשיש הבדל משפטי.
 * ⛔ בלי הבדל משפטי: אפס רשת. ⛔ ההוק אינו כותב בריפו של הלקוח (רק לתיקיית פלט זמנית) ואינו מעדכן שום מסמך.
 * ⛔ שליחה רק אם הלקוח נתן הסכמה חד-פעמית להוק (`hookConsentGiven`) בקובץ התשובות שהוא עצמו אישר. תהליך חדש לא נסקר על ידי הלקוח:
 * הוא נשלח כשינוי, ועורך הדין מבקש אישור ממנו בשיחה.
 */

import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

import { diffAgainstBaseline, isValidBaseline } from './core/client/diff'
import type { RepoFile } from './core/analyzer/types'

import { runScan } from './scan'
import { ANSWERS_FILE, transmit, type Answers, type SendOptions } from './send'

export type HookOutcome = { sent: false; reason: 'no-legal-change' } | { sent: true; scanId: string; added: readonly string[]; removed: readonly string[] }

export interface HookOptions extends Omit<SendOptions, 'prompter' | 'outDir'> {
  /** תיקיית פלט זמנית, מחוץ לקוד הנסרק (ב-CI: RUNNER_TEMP). חובה: ההוק לא כותב לשורש הריפו. */
  readonly outDir: string
  /** נתיב לקובץ הבסיס שהלקוח הכניס לריפו. */
  readonly baselinePath: string
  readonly files?: readonly RepoFile[]
}

export async function runHook(options: HookOptions): Promise<HookOutcome> {
  if (!existsSync(options.baselinePath)) throw new Error('אין קובץ בסיס. הרץ קודם send ידני, והכנס את lawstager-baseline.json לריפו')
  const baseline: unknown = JSON.parse(readFileSync(options.baselinePath, 'utf8'))
  if (!isValidBaseline(baseline)) throw new Error('קובץ הבסיס אינו תקין')

  const scan = runScan(options.root, { outDir: options.outDir, ...(options.files ? { files: options.files } : {}) })
  const diff = diffAgainstBaseline(baseline, scan.findings)
  if (!diff.significant) return { sent: false, reason: 'no-legal-change' }

  // רק מכאן יש תקשורת: התשובות והסכמת ההוק חייבות להגיע מהלקוח (סוד ב-CI או קובץ מקומי בתיקיית הפלט).
  const raw = options.answersJson ?? (existsSync(join(options.outDir, ANSWERS_FILE)) ? readFileSync(join(options.outDir, ANSWERS_FILE), 'utf8') : undefined)
  if (raw === undefined) throw new Error('אין קובץ תשובות. שליחה ידנית ראשונה נדרשת לפני שההוק יכול לשלוח')
  const answers = JSON.parse(raw) as Answers
  if (answers.consentGiven !== true || answers.hookConsentGiven !== true) throw new Error('לא ניתנה הסכמה להוק. לא נשלח דבר')

  const result = await transmit(
    {
      findings: scan.findings,
      reviews: [],
      declarationText: answers.declarationText,
      details: answers.details,
      consentGiven: true,
      runMode: options.runMode,
      hook: { added: diff.added, removed: diff.removed, baselineHash: diff.baselineHash },
    },
    scan.state,
    options,
  )
  return { sent: true, scanId: result.scanId, added: diff.added, removed: diff.removed }
}
