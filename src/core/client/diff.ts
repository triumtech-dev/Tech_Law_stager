/**
 * השוואה לבסיס שאושר (R5c, אפיון v0.2 סעיף 5.3). מודול טהור, בצד הלקוח ובבדיקות.
 *
 * הבסיס הוא סיכום קטן של הסריקה האחרונה שהלקוח שלח: סוגי הממצאים וסוג התהליך שלהם, בלי הפניות לקבצים ובלי מספרי שורות.
 * ⛔ הוק שולח דוח שינויים **רק** כשיש הבדל משפטי: סוג ממצא שנוסף או נעלם (ספק חדש, שדה מידע חדש, עוגיה חדשה, תהליך תשלום שהשתנה,
 * מנגנון הסכמה או הגנה שנעלם). שינוי במספר המופעים, בשורות או בקבצים אינו הבדל משפטי. סוגי תהליך של נגישות ואבטחה
 * (סודות, ממצאי נגישות סטטיים) לא מזעיקים: הם אינם משנים את מסמכי תנאי השימוש והפרטיות.
 * ⛔ אין שליחה על כל commit, ואין שום כתיבה לקובץ של הלקוח: ההוק רק משווה ומזעיק.
 */

import type { ProcessType } from '../analyzer/types'
import type { ClientFindingsFile } from '../client-findings'

import { canonicalJson } from './seal'
import { createHash } from 'node:crypto'

export const BASELINE_SCHEMA_VERSION = 1
/** סוגי תהליך שאינם מזעיקים הוק. */
export const SILENT_PROCESS_TYPES: readonly ProcessType[] = ['accessibility', 'security']

export interface BaselineEntry {
  readonly kind: string
  readonly processType: ProcessType
}

export interface Baseline {
  readonly schemaVersion: typeof BASELINE_SCHEMA_VERSION
  readonly entries: readonly BaselineEntry[]
}

export interface ChangeReport {
  readonly added: readonly string[]
  readonly removed: readonly string[]
  readonly baselineHash: string
}

export function baselineOf(findings: ClientFindingsFile): Baseline {
  const entries = findings.processes.map((p) => ({ kind: p.kind, processType: p.processType })).sort((a, b) => (a.kind < b.kind ? -1 : a.kind > b.kind ? 1 : 0))
  return { schemaVersion: BASELINE_SCHEMA_VERSION, entries }
}

export function hashBaseline(baseline: Baseline): string {
  return createHash('sha256').update(canonicalJson(baseline), 'utf8').digest('hex')
}

export function isValidBaseline(value: unknown): value is Baseline {
  const v = value as Baseline | null
  return (
    v !== null &&
    typeof v === 'object' &&
    v.schemaVersion === BASELINE_SCHEMA_VERSION &&
    Array.isArray(v.entries) &&
    v.entries.length <= 1_000 &&
    v.entries.every((e) => typeof e?.kind === 'string' && e.kind.length <= 200 && typeof e.processType === 'string')
  )
}

const signal = (e: BaselineEntry): boolean => !SILENT_PROCESS_TYPES.includes(e.processType)

export type DiffResult = { significant: false } | ({ significant: true } & ChangeReport)

/** משווה את הסריקה הנוכחית לבסיס. `significant` רק כשיש סוג שנוסף או נעלם בסוגי תהליך שמזעיקים. */
export function diffAgainstBaseline(baseline: Baseline, current: ClientFindingsFile): DiffResult {
  const before = new Map(baseline.entries.filter(signal).map((e) => [e.kind, e]))
  const after = new Map(baselineOf(current).entries.filter(signal).map((e) => [e.kind, e]))
  const added = [...after.keys()].filter((k) => !before.has(k)).sort()
  const removed = [...before.keys()].filter((k) => !after.has(k)).sort()
  if (added.length === 0 && removed.length === 0) return { significant: false }
  return { significant: true, added, removed, baselineHash: hashBaseline(baseline) }
}
