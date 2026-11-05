/**
 * נקודת הכניסה של המנתח הסטטי (שלב R1 בתוכנית). מקבל את קבצי הריפו בזיכרון ומחזיר ממצאים וכיסוי.
 * ⛔ קריאה בלבד: אין כאן רשת, אין כתיבה לדיסק ואין הרצה של קוד הלקוח. הבדיקה `repo-scan-readonly.test.ts` נועלת זאת.
 * ⛔ סדר הפעולות לכל קובץ: מאתרים סודות במקור, מסתירים אותם בקובץ כולו (`maskSecrets`), ורק אז מריצים
 * את שאר הגלאים, על הקובץ המוסתר בלבד. כך אף ראיה לא נבנית מטקסט שעדיין יש בו סוד (Gate A, 5.11.2026).
 */

import { MAX_FINDINGS_PER_KIND, MAX_HOST_FINDINGS } from '../constants'

import { evidenceAt, makeLocator } from './evidence'
import { extensionOf, selectFiles } from './files'
import { hostFindings } from './network'
import { runRules, type Rule } from './rules'
import { A11Y_RULES, HTML_ROOT } from './rules-a11y'
import { COMMERCE_RULES, CONTENT_ACCOUNT_RULES, DARK_PATTERN_RULES, MESSAGING_RULES } from './rules-commerce'
import { CONSENT_RULES, COOKIE_STORAGE_RULES, PERSONAL_DATA_RULES } from './rules-privacy'
import { findSecrets, maskSecrets } from './secrets'
import { TRACKER_RULES } from './trackers'
import type { AnalysisResult, Finding, RepoFile } from './types'
import { vendorFindings } from './vendors'

export const ALL_RULES: readonly Rule[] = [
  ...COOKIE_STORAGE_RULES,
  ...PERSONAL_DATA_RULES,
  ...CONSENT_RULES,
  ...COMMERCE_RULES,
  ...CONTENT_ACCOUNT_RULES,
  ...MESSAGING_RULES,
  ...DARK_PATTERN_RULES,
  ...A11Y_RULES,
  ...TRACKER_RULES,
]

/**
 * מסתיר את הקובץ ומחזיר גם ממצא `secret:<סוג>` לכל סוד שאינו placeholder.
 * ⛔ לממצא סוד אין טקסט מהשורה: שורה עם סוד מוכר נושאת לעיתים קרובות סוד נוסף בלי תבנית (`AWS_SECRET_ACCESS_KEY`
 * ליד `AKIA…`). הראיה היא תיאור קבוע, והקובץ והשורה מספיקים לעורך הדין ולמפתח.
 */
function maskFile(file: RepoFile): { masked: RepoFile; secrets: Finding[] } {
  const hits = findSecrets(file.text)
  if (hits.length === 0) return { masked: file, secrets: [] }
  const masked: RepoFile = { path: file.path, text: maskSecrets(file.text, hits) }
  const locator = makeLocator(file.text)
  const secrets = hits
    .filter((hit) => !hit.placeholder)
    .map((hit): Finding => ({ kind: `secret:${hit.id}`, processType: 'security', path: file.path, line: locator.lineAt(hit.index), evidence: SECRET_EVIDENCE, confidence: 'high' }))
  return { masked, secrets }
}

export const SECRET_EVIDENCE = '[REDACTED]: נמצא ערך סודי בשורה הזו. הערך אינו נשמר'

/** `<html>` בלי `lang` או בלי `dir`: ממצא נגישות לכל קובץ מסמך. */
function htmlRootFindings(file: RepoFile): Finding[] {
  if (!['html', 'htm', 'tsx', 'jsx', 'php', 'astro', 'vue'].includes(extensionOf(file.path))) return []
  const locator = makeLocator(file.text)
  const out: Finding[] = []
  for (const m of file.text.matchAll(HTML_ROOT)) {
    if (m.index === undefined) continue
    const attrs = m[1] ?? ''
    const line = locator.lineAt(m.index)
    const evidence = evidenceAt(locator.lineText(line), m.index - locator.lineStart(line))
    if (!/\blang\s*=/i.test(attrs)) out.push({ kind: 'html_without_lang', processType: 'accessibility', path: file.path, line, evidence, confidence: 'high' })
    if (!/\bdir\s*=/i.test(attrs)) out.push({ kind: 'html_without_dir', processType: 'accessibility', path: file.path, line, evidence, confidence: 'medium' })
  }
  return out
}

function byLocation(a: Finding, b: Finding): number {
  if (a.path !== b.path) return a.path < b.path ? -1 : 1
  if (a.line !== b.line) return a.line - b.line
  return a.kind < b.kind ? -1 : a.kind > b.kind ? 1 : 0
}

/**
 * מנתח את הריפו. סדר הממצאים יציב (נתיב, שורה, סוג). עד `MAX_FINDINGS_PER_KIND` לכל סוג,
 * ועד `MAX_HOST_FINDINGS` מארחים בסך הכול (כל מארח הוא סוג משלו, ובלי תקרה כוללת הרשימה לא חסומה).
 * קבצי בדיקה לא נסרקים לתהליכים, אבל כן לסודות: מפתחות אמיתיים נשכחים גם שם.
 */
export function analyzeRepo(input: readonly RepoFile[]): AnalysisResult {
  const { files, secretsOnly, coverage } = selectFiles(input)
  const all: Finding[] = []
  for (const file of secretsOnly) all.push(...maskFile(file).secrets)
  for (const file of files) {
    const { masked, secrets } = maskFile(file)
    // קובצי התלויות נקראים מהמקור: הסתרה שוברת JSON הייתה מעלימה ספקים בשקט, והראיה (שם החבילה) עוברת `evidenceFor`.
    all.push(...secrets, ...vendorFindings(file), ...hostFindings(masked), ...htmlRootFindings(masked), ...runRules(masked, ALL_RULES))
  }
  all.sort(byLocation)
  const totals: Record<string, number> = {}
  const findings: Finding[] = []
  let hosts = 0
  for (const finding of all) {
    const count = (totals[finding.kind] ?? 0) + 1
    totals[finding.kind] = count
    if (count > MAX_FINDINGS_PER_KIND) continue
    if (finding.kind.startsWith('host:')) {
      hosts += 1
      if (hosts > MAX_HOST_FINDINGS) continue
    }
    findings.push(finding)
  }
  return { findings, totals, coverage }
}
