#!/usr/bin/env node
/**
 * סטאג'ר משפטי, חבילת הסריקה: שורת הפקודה. שני שלבים:
 *   scan [תיקייה]            סריקה מקומית, בלי רשת. כותב ל-.lawstager/
 *   send [תיקייה] [--lawyer מזהה] [--ci --answers-env שם]   שליחה אחרי שקראת. --ci רק מתוך GitHub Actions (מסלול מאומת)
 * ⛔ החבילה אינה מריצה קוד של הלקוח, אינה כותבת מחוץ ל-.lawstager/ ולקובץ התשובות, ואינה שולחת קוד.
 */

import { createInterface } from 'node:readline/promises'
import { resolve } from 'node:path'

import { runHook } from './hook'
import { runScan, OUT_DIR_NAME } from './scan'
import { ANSWERS_FILE, runSend, type Prompter } from './send'


function flag(args: readonly string[], name: string): string | undefined {
  const index = args.indexOf(`--${name}`)
  return index >= 0 ? args[index + 1] : undefined
}

function terminalPrompter(): Prompter & { close(): void } {
  const rl = createInterface({ input: process.stdin, output: process.stdout })
  return { say: (text) => console.log(text), ask: (question) => rl.question(question), close: () => rl.close() }
}

/** אסימון OIDC של GitHub Actions בקהל נתון. זמין רק בתוך workflow עם `id-token: write`. */
async function fetchOidcToken(audience: string): Promise<string> {
  const url = process.env.ACTIONS_ID_TOKEN_REQUEST_URL
  const bearer = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN
  if (!url || !bearer) throw new Error('אין אסימון OIDC: --ci רץ רק מתוך GitHub Actions עם הרשאת id-token')
  const response = await fetch(`${url}&audience=${encodeURIComponent(audience)}`, { headers: { authorization: `Bearer ${bearer}` } })
  if (!response.ok) throw new Error('קבלת אסימון OIDC נכשלה')
  const body = (await response.json()) as { value?: string }
  if (!body.value) throw new Error('אסימון OIDC חסר בתשובה')
  return body.value
}

async function main(args: readonly string[]): Promise<number> {
  const [command, maybeDir] = args
  const root = resolve(maybeDir && !maybeDir.startsWith('--') ? maybeDir : '.')
  if (command === 'scan') {
    const out = runScan(root, { outDir: flag(args, 'out') })
    console.log(out.preview)
    console.log(`\nהקבצים נכתבו ל-${out.outDir}. קרא אותם, ואז הרץ: send`)
    return 0
  }
  if (command === 'send') {
    const ci = args.includes('--ci')
    const answersEnv = flag(args, 'answers-env')
    if (ci && !answersEnv) throw new Error('--ci דורש --answers-env: התשובות עוברות כסוד, לא כקובץ בריפו')
    const prompter = ci ? undefined : terminalPrompter()
    try {
      const result = await runSend({
        root,
        lawyerId: flag(args, 'lawyer'),
        endpoint: flag(args, 'endpoint'),
        runMode: ci ? 'github-actions' : 'local',
        fetchFn: fetch,
        prompter,
        outDir: flag(args, 'out'),
        answersJson: answersEnv ? process.env[answersEnv] : undefined,
        getOidcToken: ci ? fetchOidcToken : undefined,
        commit: ci ? process.env.GITHUB_SHA : undefined,
        runId: ci ? process.env.GITHUB_RUN_ID : undefined,
      })
      console.log(`נשלח. מספר הסריקה: ${result.scanId}`)
      if (!ci) {
        console.log(`התשובות נשמרו ב-${OUT_DIR_NAME}/${ANSWERS_FILE} ואינן נכנסות ל-git. למסלול המאומת: העתק את תוכן הקובץ לסוד LAWSTAGER_ANSWERS ב-GitHub. אל תוסיף אותו לריפו: יש בו פרטי קשר.`)
      }
      return 0
    } finally {
      prompter?.close()
    }
  }
  if (command === 'hook') {
    const ci = args.includes('--ci')
    const answersEnv = flag(args, 'answers-env')
    const out = flag(args, 'out') ?? process.env.RUNNER_TEMP
    if (!out) throw new Error('הוק דורש --out (תיקיית פלט זמנית מחוץ לריפו)')
    const outcome = await runHook({
      root,
      lawyerId: flag(args, 'lawyer'),
      endpoint: flag(args, 'endpoint'),
      runMode: ci ? 'github-actions' : 'local',
      fetchFn: fetch,
      outDir: resolve(out, 'lawstager-hook'),
      baselinePath: resolve(root, flag(args, 'baseline') ?? 'lawstager-baseline.json'),
      answersJson: answersEnv ? process.env[answersEnv] : undefined,
      getOidcToken: ci ? fetchOidcToken : undefined,
      commit: ci ? process.env.GITHUB_SHA : undefined,
      runId: ci ? process.env.GITHUB_RUN_ID : undefined,
    })
    console.log(outcome.sent ? `נשלח דוח שינויים. מספר הסריקה: ${outcome.scanId}. עדכן את lawstager-baseline.json אחרי שעורך הדין אישר.` : 'אין שינוי משפטי. לא נשלח דבר.')
    return 0
  }
  console.log('שימוש: scan [תיקייה] | send [תיקייה] [--lawyer מזהה] [--ci] | hook [תיקייה] --out תיקייה [--baseline קובץ] [--ci --answers-env שם]')
  return 1
}

main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (error: unknown) => {
    console.error(error instanceof Error ? error.message : 'שגיאה לא צפויה')
    process.exit(1)
  },
)
