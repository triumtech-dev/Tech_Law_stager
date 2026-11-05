/**
 * סטאג'ר משפטי, חבילת הסריקה: קריאת קבצי הפרויקט מהדיסק (קריאה בלבד).
 * ⛔ לא מריץ קוד של הלקוח, לא כותב לתיקיית המקור ולא פותח רשת. דילוג על תיקיות תלויות ובנייה כבר בטיול,
 * כדי לא לקרוא אלפי קבצים שהמנתח ידלג עליהם (המנתח עדיין סופר דילוגים לפי הנתיב).
 */

import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative, sep } from 'node:path'

import { MAX_FILE_BYTES, MAX_FILES_READ_INVENTED } from './core/constants'
import type { RepoFile } from './core/analyzer/types'

const SKIP_DIRS = new Set(['node_modules', '.git', '.next', 'dist', 'build', 'out', 'vendor', '.venv', '__pycache__'])
// תיקיית הפלט של הכלי מדולגת רק בשורש, כדי שסריקה חוזרת לא תקרא את הפלט הקודם.
// ⛔ לא בעומק: תיקייה בשם הזה בתוך הקוד של הלקוח הייתה מסתירה קוד מהסריקה.
const OUTPUT_DIR = '.lawstager'

/** מטייל בתיקייה ומחזיר קבצים כטקסט. קובץ שאינו קריא או גדול מדי לא נכלל (המנתח אינו רואה אותו). */
export function readProjectFiles(root: string): RepoFile[] {
  const out: RepoFile[] = []
  const visit = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (out.length >= MAX_FILES_READ_INVENTED) return
      if (entry.isSymbolicLink()) continue
      const full = join(dir, entry.name)
      if (entry.isDirectory()) {
        const skipOutput = dir === root && entry.name === OUTPUT_DIR
        if (!SKIP_DIRS.has(entry.name) && !skipOutput) visit(full)
        continue
      }
      if (!entry.isFile()) continue
      try {
        if (statSync(full).size > MAX_FILE_BYTES) continue
        const text = readFileSync(full, 'utf8')
        if (text.includes('\u0000')) continue
        out.push({ path: relative(root, full).split(sep).join('/'), text })
      } catch {
        // קובץ שאי אפשר לקרוא מדולג, ולא עוצר את הסריקה.
      }
    }
  }
  visit(root)
  return out
}
