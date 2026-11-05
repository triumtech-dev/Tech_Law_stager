/**
 * ולידטור קשיח לקובץ הממצאים (Gate A, 5.11.2026). רץ בשני הצדדים: בחבילה לפני האישור והשליחה, ובשרת אחרי פתיחת המעטפת.
 * ⛔ דוחה כל מפתח עודף, סוג שאינו מוכר ושדה בצורה שגויה, ולא "מנקה": קובץ שנערך ידנית כדי להכניס טקסט, קטע קוד או סוד
 * לשדה כלשהו לא יעבור. ה-hash של ממצאים תקינים זהה לזה של המקור, כי הצורה הקנונית זהה.
 */

import { PROCESS_TYPES, SKIP_REASONS } from '../analyzer/types'
import { CLIENT_FINDINGS_SCHEMA_VERSION, REFERENCES_PER_KIND_INVENTED, type ClientFindingsFile } from '../client-findings'

import type { ChangeReport } from './diff'

export const MAX_PROCESSES_INVENTED = 600
const KIND_PATTERN = /^[A-Za-z0-9_:.*\-]{1,200}$/
const EXT_PATTERN = /^[A-Za-z0-9_+\-]{0,16}$/
const MAX_PATH = 300
const MAX_INT = 1_000_000_000

type Obj = Record<string, unknown>

function isObj(value: unknown): value is Obj {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function exactKeys(value: Obj, keys: readonly string[]): boolean {
  const own = Object.keys(value)
  return own.length === keys.length && keys.every((k) => own.includes(k))
}

function isInt(value: unknown, min = 0): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= min && value <= MAX_INT
}

function safePath(value: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_PATH) return false
  for (let i = 0; i < value.length; i += 1) {
    const c = value.charCodeAt(i)
    if (c < 32 || c === 127) return false
  }
  return !value.startsWith('/') && !value.includes('..')
}

function validCoverage(value: unknown): boolean {
  if (!isObj(value) || !exactKeys(value, ['filesRead', 'bytesRead', 'skipped', 'byExtension'])) return false
  if (!isInt(value.filesRead) || !isInt(value.bytesRead)) return false
  const skipped = value.skipped
  if (!isObj(skipped) || !exactKeys(skipped, SKIP_REASONS) || !SKIP_REASONS.every((r) => isInt(skipped[r]))) return false
  const ext = value.byExtension
  if (!isObj(ext) || Object.keys(ext).length > 200) return false
  return Object.entries(ext).every(([k, v]) => EXT_PATTERN.test(k) && isInt(v))
}

function validProcess(value: unknown): boolean {
  if (!isObj(value) || !exactKeys(value, ['kind', 'processType', 'confidence', 'count', 'references'])) return false
  if (typeof value.kind !== 'string' || !KIND_PATTERN.test(value.kind)) return false
  if (!(PROCESS_TYPES as readonly string[]).includes(value.processType as string)) return false
  if (value.confidence !== 'high' && value.confidence !== 'medium' && value.confidence !== 'low') return false
  if (!isInt(value.count)) return false
  const refs = value.references
  if (!Array.isArray(refs) || refs.length > REFERENCES_PER_KIND_INVENTED) return false
  return refs.every((r) => isObj(r) && exactKeys(r, ['path', 'line']) && safePath(r.path) && isInt(r.line, 1))
}

/** דוח שינויים של הוק: שתי רשימות סוגים חסומות ו-hash של הבסיס. בלי מפתחות עודפים. */
export function isValidChangeReport(value: unknown): value is ChangeReport {
  if (!isObj(value) || !exactKeys(value, ['added', 'removed', 'baselineHash'])) return false
  if (typeof value.baselineHash !== 'string' || !/^[0-9a-f]{64}$/.test(value.baselineHash)) return false
  const okList = (l: unknown): boolean => Array.isArray(l) && l.length <= MAX_PROCESSES_INVENTED && l.every((k) => typeof k === 'string' && KIND_PATTERN.test(k))
  return okList(value.added) && okList(value.removed)
}

/** `true` רק לקובץ ממצאים בצורה המדויקת שהחבילה מפיקה. */
export function isValidFindingsFile(value: unknown): value is ClientFindingsFile {
  if (!isObj(value) || !exactKeys(value, ['schemaVersion', 'analyzerVersion', 'processes', 'coverage', 'partialCoverage'])) return false
  if (value.schemaVersion !== CLIENT_FINDINGS_SCHEMA_VERSION) return false
  if (typeof value.analyzerVersion !== 'string' || !/^[0-9A-Za-z.\-]{1,32}$/.test(value.analyzerVersion)) return false
  if (typeof value.partialCoverage !== 'boolean') return false
  const processes = value.processes
  if (!Array.isArray(processes) || processes.length > MAX_PROCESSES_INVENTED || !processes.every(validProcess)) return false
  return validCoverage(value.coverage)
}
