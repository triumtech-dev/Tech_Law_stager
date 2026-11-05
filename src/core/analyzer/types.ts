/**
 * הטיפוסים של מנתח הריפו. מודול טהור: בלי רשת, בלי `firebase-admin`, בלי כתיבה לדיסק.
 * ⛔ הקלט הוא קוד של לקוח (מידע מוגבל, §13). שום שדה בפלט אינו נושא ערך של סוד (ראו `secrets.ts`).
 */

/** קובץ מהריפו, כטקסט בזיכרון. `path` יחסי לשורש הריפו, עם `/`. */
export interface RepoFile {
  readonly path: string
  readonly text: string
}

/** סוגי התהליכים שהדוח ממפה לחובות בקטלוג (אפיון סעיף 5). */
export const PROCESS_TYPES = [
  'personal_data',
  'cookies_storage',
  'third_party',
  'payments',
  'subscription',
  'distance_sale',
  'user_content',
  'marketing',
  'notifications',
  'account',
  'minors',
  'dark_pattern',
  'accessibility',
  'security',
] as const
export type ProcessType = (typeof PROCESS_TYPES)[number]

export type Confidence = 'high' | 'medium' | 'low'

export interface Finding {
  /** מזהה סגור של סוג הממצא, למשל `cookie_write` או `tracker:google-analytics`. */
  readonly kind: string
  readonly processType: ProcessType
  readonly path: string
  /** מספר שורה, מ-1. */
  readonly line: number
  /** קטע קצר מהשורה, אחרי הסרת סודות. */
  readonly evidence: string
  readonly confidence: Confidence
}

export const SKIP_REASONS = ['dependency_dir', 'build_dir', 'not_text', 'binary', 'minified', 'too_large', 'test', 'over_limit'] as const
export type SkipReason = (typeof SKIP_REASONS)[number]

export interface ScanCoverage {
  readonly filesRead: number
  readonly bytesRead: number
  readonly skipped: Readonly<Record<SkipReason, number>>
  /** קבצים שנקראו לפי סיומת, למשל `{ ts: 40, py: 2 }`. */
  readonly byExtension: Readonly<Record<string, number>>
}

export interface AnalysisResult {
  /** עד `MAX_FINDINGS_PER_KIND` לכל סוג, ממוינים לפי נתיב ושורה. */
  readonly findings: readonly Finding[]
  /** כמה ממצאים היו לכל סוג לפני התקרה. */
  readonly totals: Readonly<Record<string, number>>
  readonly coverage: ScanCoverage
}
