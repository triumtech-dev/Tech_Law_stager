/**
 * אילו קבצים מהריפו נקראים. רשימה סגורה של סיומות טקסט, ודילוג על תלויות, תוצרי בנייה,
 * קבצים בינאריים, קבצים ממוזערים ובדיקות. כל דילוג נספר, כדי שהדוח יציג כיסוי אמיתי ולא "נסרק הכול".
 */

import { MAX_FILE_BYTES, MAX_FILES_READ_INVENTED, MINIFIED_AVG_LINE } from '../constants'

import { SKIP_REASONS, type RepoFile, type ScanCoverage, type SkipReason } from './types'

const TEXT_EXTENSIONS = new Set([
  'js', 'jsx', 'mjs', 'cjs', 'ts', 'tsx', 'mts', 'cts', 'vue', 'svelte', 'astro',
  'html', 'htm', 'php', 'py', 'rb', 'go', 'java', 'kt', 'swift', 'dart', 'cs',
  'json', 'yaml', 'yml', 'toml', 'xml', 'txt', 'md', 'env', 'rules', 'css', 'scss', 'sass', 'less',
  // קבצים שנושאים סודות לעיתים קרובות: נקראים כדי שהסוד יזוהה ויוסתר
  'pem', 'key', 'ini', 'properties', 'tf', 'tfvars', 'sh', 'cfg', 'conf',
])
/** קבצים בלי סיומת מוכרת שנקראים לפי שם. */
const TEXT_NAMES = new Set(['dockerfile', 'gemfile', 'requirements.txt', 'pipfile', 'procfile', '.env', '.npmrc', '.pypirc', '.netrc'])

const encoder = new TextEncoder()
/** גודל בבתים (UTF-8). עברית היא שני בתים לתו, ולכן `length` לבדו מטעה. */
function byteLength(text: string): number {
  // כל תו הוא בית אחד לפחות, ולכן טקסט ארוך מהתקרה בתווים חורג ממנה גם בבתים, בלי לקודד מגה-בייטים לחינם.
  return text.length > MAX_FILE_BYTES ? text.length : encoder.encode(text).length
}

const DEPENDENCY_DIRS = new Set(['node_modules', 'vendor', 'bower_components', '.venv', 'venv', '__pycache__', 'pods', '.git'])
const BUILD_DIRS = new Set(['dist', 'build', 'out', '.next', '.nuxt', '.output', 'coverage', '.firebase', '.turbo', '.cache', 'lib-cov'])

function segments(path: string): string[] {
  return path.split('/').filter((s) => s !== '')
}

export function extensionOf(path: string): string {
  const name = segments(path).at(-1) ?? ''
  const dot = name.lastIndexOf('.')
  return dot <= 0 ? '' : name.slice(dot + 1).toLowerCase()
}

function isTextFile(path: string): boolean {
  const name = (segments(path).at(-1) ?? '').toLowerCase()
  if (TEXT_NAMES.has(name) || name.startsWith('.env.')) return true
  return TEXT_EXTENSIONS.has(extensionOf(path))
}

function isTestPath(path: string): boolean {
  const lower = path.toLowerCase()
  return /(^|\/)(__tests__|__mocks__|test|tests|spec|e2e|cypress|fixtures?)\//.test(lower) || /\.(test|spec|stories)\.[a-z]+$/.test(lower)
}

function isMinified(path: string, text: string): boolean {
  if (/\.min\.(js|css)$/i.test(path)) return true
  const lines = text.split('\n').length
  return text.length > 5_000 && text.length / lines > MINIFIED_AVG_LINE
}

/** סיבת הדילוג, או `null` כשהקובץ נקרא. */
export function skipReason(file: RepoFile): SkipReason | null {
  const segs = segments(file.path).slice(0, -1).map((s) => s.toLowerCase())
  if (segs.some((s) => DEPENDENCY_DIRS.has(s))) return 'dependency_dir'
  if (segs.some((s) => BUILD_DIRS.has(s))) return 'build_dir'
  if (!isTextFile(file.path)) return 'not_text'
  if (byteLength(file.text) > MAX_FILE_BYTES) return 'too_large'
  if (file.text.includes('\u0000')) return 'binary'
  if (isTestPath(file.path)) return 'test'
  if (isMinified(file.path, file.text)) return 'minified'
  return null
}

export interface FileSelection {
  readonly files: readonly RepoFile[]
  /** קבצי בדיקה: לא נסרקים לתהליכים, רק לסודות. */
  readonly secretsOnly: readonly RepoFile[]
  readonly coverage: ScanCoverage
}

/** בוחר את הקבצים שנקראים, בסדר נתיבים יציב, ומחזיר את הכיסוי. */
export function selectFiles(input: readonly RepoFile[]): FileSelection {
  const skipped = Object.fromEntries(SKIP_REASONS.map((r) => [r, 0])) as Record<SkipReason, number>
  const byExtension: Record<string, number> = {}
  const files: RepoFile[] = []
  const secretsOnly: RepoFile[] = []
  let bytesRead = 0
  const sorted = [...input].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))
  for (const file of sorted) {
    const reason = skipReason(file)
    if (reason !== null) {
      skipped[reason] += 1
      if (reason === 'test' && secretsOnly.length < MAX_FILES_READ_INVENTED) secretsOnly.push(file)
      continue
    }
    if (files.length >= MAX_FILES_READ_INVENTED) {
      skipped.over_limit += 1
      continue
    }
    files.push(file)
    bytesRead += byteLength(file.text)
    const ext = extensionOf(file.path) || 'other'
    byExtension[ext] = (byExtension[ext] ?? 0) + 1
  }
  return { files, secretsOnly, coverage: { filesRead: files.length, bytesRead, skipped, byExtension } }
}
