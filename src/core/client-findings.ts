/**
 * קובץ הממצאים שחבילת הלקוח כותבת ושולחת (D-064, אפיון v0.2 סעיף 7).
 * ⛔ מכיל תהליכים, ספקים והפניות (נתיב ושורה) בלבד. בלי `evidence`, ולכן בלי שום קטע קוד.
 * מודול טהור: בלי רשת, בלי `firebase-admin`, בלי כתיבה לדיסק. החתימה וההצפנה (סעיף 6א) נוספות בשלב R4b.
 */

import type { AnalysisResult, Confidence, Finding, ProcessType, ScanCoverage } from './analyzer/types'

/** גרסת מבנה הקובץ. שינוי במבנה מחייב העלאה, והשרת דוחה גרסה שאינו מכיר. */
export const CLIENT_FINDINGS_SCHEMA_VERSION = 1
/** כמה הפניות (נתיב ושורה) נשמרות לכל סוג ממצא. הספירה המלאה נשמרת תמיד. */
export const REFERENCES_PER_KIND_INVENTED = 5

export interface FindingReference {
  readonly path: string
  readonly line: number
}

export interface ClientProcessEntry {
  readonly kind: string
  readonly processType: ProcessType
  /** הרמה הגבוהה ביותר בין הממצאים מאותו סוג. */
  readonly confidence: Confidence
  /** כמה פעמים נמצא בקוד, כולל מעבר לתקרת ההפניות. */
  readonly count: number
  readonly references: readonly FindingReference[]
}

export interface ClientFindingsFile {
  readonly schemaVersion: typeof CLIENT_FINDINGS_SCHEMA_VERSION
  /** גרסת המנתח שהפיק את הקובץ (הדוח של עורך הדין מציג אותה). */
  readonly analyzerVersion: string
  readonly processes: readonly ClientProcessEntry[]
  readonly coverage: ScanCoverage
  /** נכון כשקבצים דולגו בגלל גודל או תקרה, ולכן הדוח מסומן "כיסוי חלקי". */
  readonly partialCoverage: boolean
}

const CONFIDENCE_RANK: Readonly<Record<Confidence, number>> = { low: 0, medium: 1, high: 2 }

function byLocation(a: Finding, b: Finding): number {
  return a.path === b.path ? a.line - b.line : a.path < b.path ? -1 : 1
}

/** ממיר פלט של המנתח לקובץ שנשלח. אינו מעתיק את `evidence` לשום שדה. */
export function buildClientFindings(result: AnalysisResult, analyzerVersion: string): ClientFindingsFile {
  const groups = new Map<string, Finding[]>()
  for (const finding of result.findings) {
    const list = groups.get(finding.kind)
    if (list) list.push(finding)
    else groups.set(finding.kind, [finding])
  }

  const processes: ClientProcessEntry[] = [...groups.entries()]
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([kind, list]) => {
      const sorted = [...list].sort(byLocation)
      const confidence = sorted.reduce<Confidence>(
        (best, f) => (CONFIDENCE_RANK[f.confidence] > CONFIDENCE_RANK[best] ? f.confidence : best),
        'low',
      )
      return {
        kind,
        processType: sorted[0]?.processType ?? 'security',
        confidence,
        count: Math.max(result.totals[kind] ?? 0, sorted.length),
        references: sorted.slice(0, REFERENCES_PER_KIND_INVENTED).map((f) => ({ path: f.path, line: f.line })),
      }
    })

  const { skipped } = result.coverage
  return {
    schemaVersion: CLIENT_FINDINGS_SCHEMA_VERSION,
    analyzerVersion,
    processes,
    coverage: result.coverage,
    partialCoverage: skipped.too_large > 0 || skipped.over_limit > 0,
  }
}
