/**
 * סטאג'ר משפטי, חבילת הסריקה: שלב 1 (סריקה מקומית). בלי רשת. כותב לתיקיית `.lawstager/` בלבד:
 * `lawstager-findings.json` (הממצאים, בלי קוד), `lawstager-preview.txt` (תצוגה לקריאה) ו-`scan-state.json`.
 */

import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

import { analyzeRepo } from './core/analyzer/analyze'
import { buildClientFindings, type ClientFindingsFile } from './core/client-findings'
import { renderPreview } from './core/client/preview'
import { computeTreeDigest, hashFindings } from './core/client/seal'
import type { RepoFile } from './core/analyzer/types'

import { readProjectFiles } from './walk'

/** גרסת החבילה והמנתח, מופיעה בדוח של עורך הדין. */
export const ANALYZER_VERSION = '0.1.0'
export const OUT_DIR_NAME = '.lawstager'
export const FINDINGS_FILE = 'lawstager-findings.json'
export const PREVIEW_FILE = 'lawstager-preview.txt'
export const STATE_FILE = 'scan-state.json'

export interface ScanState {
  readonly analyzerVersion: string
  readonly treeDigest: string
  readonly findingsHash: string
  readonly scannedAtMs: number
}

export interface ScanOutput {
  readonly findings: ClientFindingsFile
  readonly state: ScanState
  readonly preview: string
  readonly outDir: string
}

/** מריץ את המנתח על קבצים בזיכרון וכותב את שלושת הקבצים. `files` מאפשר לבדיקות להזין קלט בלי דיסק. */
export function runScan(root: string, options: { files?: readonly RepoFile[]; now?: () => number; outDir?: string } = {}): ScanOutput {
  const files = options.files ?? readProjectFiles(root)
  const findings = buildClientFindings(analyzeRepo(files), ANALYZER_VERSION)
  const preview = renderPreview(findings)
  const state: ScanState = {
    analyzerVersion: ANALYZER_VERSION,
    treeDigest: computeTreeDigest(files),
    findingsHash: hashFindings(findings),
    scannedAtMs: (options.now ?? Date.now)(),
  }
  const outDir = options.outDir ?? join(root, OUT_DIR_NAME)
  mkdirSync(outDir, { recursive: true })
  // התיקייה כוללת תשובות עם פרטי קשר: `*` מונע מ-git להוסיף אותה בטעות (ממצא אבטחה, 5.11.2026).
  writeFileSync(join(outDir, '.gitignore'), '*\n', 'utf8')
  writeFileSync(join(outDir, FINDINGS_FILE), `${JSON.stringify(findings, null, 2)}\n`, 'utf8')
  writeFileSync(join(outDir, PREVIEW_FILE), `${preview}\n`, 'utf8')
  writeFileSync(join(outDir, STATE_FILE), `${JSON.stringify(state, null, 2)}\n`, 'utf8')
  return { findings, state, preview, outDir }
}
