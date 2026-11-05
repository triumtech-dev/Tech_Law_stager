/**
 * סטאג'ר משפטי, חבילת הסריקה: שלב 2 (שליחה). הרשת נפתחת כאן ורק כאן, ורק אחרי שהלקוח קרא ואישר.
 * ⛔ נשלחת מעטפת אטומה בלבד. הקוד עצמו אינו נקרא בשלב הזה: הקלט הוא קובצי `.lawstager/` שהשלב הקודם כתב.
 * ב-GitHub Actions אין שאלות: התשובות נקראות מקובץ שהלקוח הפיק מקומית, ושלב הסריקה בענן חייב להפיק ממצאים
 * זהים (אותו hash) לאלה שהלקוח אישר. הפרש מפסיק את השליחה.
 */

import { randomUUID } from 'node:crypto'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

import type { ClientFindingsFile } from './core/client-findings'
import { CLIENT_SCAN_CONSENT_CHECKBOX, CLIENT_SCAN_CONSENT_PARAGRAPHS, HOOK_CONSENT_CHECKBOX } from './core/client/consent'
import { reviewItems } from './core/client/preview'
import {
  BEGIN_FUNCTION,
  LAWSTAGER_ENDPOINT_INVENTED,
  POOL_LAWYER_ID,
  SUBMIT_FUNCTION,
  type BeginResponse,
  type SubmitResponse,
} from './core/client/protocol'
import { hashFindings, sealSubmission } from './core/client/seal'
import { baselineOf } from './core/client/diff'
import { buildSubmission, type ClientDetails, type ProcessReview, type RunMode, type SubmissionInput } from './core/client/submission'

import { FINDINGS_FILE, OUT_DIR_NAME, STATE_FILE, type ScanState } from './scan'

export const ANSWERS_FILE = 'lawstager-answers.json'
export const BASELINE_FILE = 'lawstager-baseline.json'

export interface Answers {
  readonly findingsHash: string
  readonly details: ClientDetails
  readonly reviews: readonly ProcessReview[]
  readonly declarationText: string
  readonly consentGiven: boolean
  /** הסכמה חד-פעמית לשליחה אוטומטית של דוחות שינויים מההוק. */
  readonly hookConsentGiven?: boolean
}

export interface Prompter {
  say(_text: string): void
  ask(_question: string): Promise<string>
}

export interface SendOptions {
  readonly root: string
  readonly lawyerId?: string
  readonly endpoint?: string
  readonly runMode: RunMode
  readonly fetchFn: typeof fetch
  readonly prompter?: Prompter
  /** תיקיית הפלט של הסריקה. ברירת מחדל: `.lawstager/` בשורש. ב-CI: תיקיית זמני, מחוץ לקוד הנסרק. */
  readonly outDir?: string
  /** תוכן קובץ התשובות כשהוא מגיע מסוד (CI). ⛔ פרטי קשר לא נשמרים בריפו (ממצא אבטחה, 5.11.2026). */
  readonly answersJson?: string
  /** מבקש אסימון OIDC בקהל נתון. קיים רק ב-GitHub Actions. הקהל של השליחה קשור ל-nonce. */
  readonly getOidcToken?: (_audience: string) => Promise<string>
  readonly commit?: string
  readonly runId?: string
}

function readJson<T>(path: string): T {
  if (!existsSync(path)) throw new Error(`הקובץ ${path} לא נמצא. הרץ קודם את שלב הסריקה (scan)`)
  return JSON.parse(readFileSync(path, 'utf8')) as T
}

const YES = new Set(['כן', 'y', 'yes', 'Y'])

async function collectAnswers(findings: ClientFindingsFile, hash: string, prompter: Prompter): Promise<Answers> {
  prompter.say('עבור על התהליכים שנמצאו. לכל אחד: "כן" אם זה מה שהמערכת עושה, או "לא" אם אינך מסכים או אינך בטוח.')
  const reviews: ProcessReview[] = []
  for (const item of reviewItems(findings)) {
    prompter.say(`\n${item.description} (נמצא ${item.count} פעמים)`)
    const answer = (await prompter.ask('נכון? (כן/לא): ')).trim()
    if (YES.has(answer)) reviews.push({ kind: item.kind, verdict: 'agree' })
    else reviews.push({ kind: item.kind, verdict: 'disagree', note: await prompter.ask('הסבר קצר: ') })
  }
  prompter.say('\nפרטי המערכת ואיש הקשר, כדי שעורך הדין ידע עם מי להתכתב:')
  const details: ClientDetails = {
    systemName: await prompter.ask('שם המערכת: '),
    siteUrl: await prompter.ask('כתובת האתר (https://...): '),
    contactName: await prompter.ask('שם איש הקשר: '),
    contactEmail: await prompter.ask('מייל: '),
    contactPhone: await prompter.ask('טלפון (אפשר להשאיר ריק): '),
  }
  prompter.say('\nמלל חופשי (לא חובה): תהליכים עתידיים שעוד לא בקוד, או פרטים משפטיים מדויקים (שם התאגיד כפי שהוא רשום, כתובת, מספר רישום). הטקסט יסומן "הצהרת לקוח, לא אומת".')
  const declarationText = await prompter.ask('הצהרה: ')
  prompter.say(`\n${CLIENT_SCAN_CONSENT_PARAGRAPHS.join('\n\n')}`)
  const consent = await prompter.ask(`${CLIENT_SCAN_CONSENT_CHECKBOX}\nמסכים? (כן/לא): `)
  const given = YES.has(consent.trim())
  let hookConsentGiven = false
  if (given) {
    prompter.say('\nאופציונלי: הוק שבודק בכל שינוי בקוד אם השתנה משהו משפטי, ושולח דוח שינויים רק אם כן.')
    hookConsentGiven = YES.has((await prompter.ask(`${HOOK_CONSENT_CHECKBOX}\nמסכים? (כן/לא): `)).trim())
  }
  return { findingsHash: hash, details, reviews, declarationText, consentGiven: given, hookConsentGiven }
}

async function callFunction<T>(fetchFn: typeof fetch, endpoint: string, name: string, data: unknown): Promise<T> {
  const response = await fetchFn(`${endpoint}/${name}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ data }),
  })
  if (!response.ok) throw new Error(`השרת דחה את הבקשה (${response.status})`)
  const body = (await response.json()) as { result?: T }
  if (!body.result) throw new Error('תשובת השרת אינה תקינה')
  return body.result
}

/** מבצע את שלב 2. מחזיר את מזהה הסריקה שהשרת נתן. */
export async function runSend(options: SendOptions): Promise<SubmitResponse> {
  const dir = options.outDir ?? join(options.root, OUT_DIR_NAME)
  const findings = readJson<ClientFindingsFile>(join(dir, FINDINGS_FILE))
  const state = readJson<ScanState>(join(dir, STATE_FILE))
  const hash = hashFindings(findings)
  if (hash !== state.findingsHash) throw new Error('קובץ הממצאים שונה אחרי הסריקה. הרץ סריקה מחדש')

  // התשובות נשמרות בתוך תיקיית הפלט (שיש בה `.gitignore` עם `*`), לא בשורש הקוד.
  const answersPath = join(dir, ANSWERS_FILE)
  let answers: Answers
  if (options.prompter) {
    answers = await collectAnswers(findings, hash, options.prompter)
    writeFileSync(answersPath, `${JSON.stringify(answers, null, 2)}\n`, 'utf8')
  } else {
    answers = options.answersJson !== undefined ? (JSON.parse(options.answersJson) as Answers) : readJson<Answers>(answersPath)
    if (answers.findingsHash !== hash) throw new Error('הממצאים השתנו מאז שאישרת אותם. הרץ שוב את השליחה האינטראקטיבית')
  }

  const result = await transmit(
    { findings, reviews: answers.reviews, declarationText: answers.declarationText, details: answers.details, consentGiven: answers.consentGiven, runMode: options.runMode },
    state,
    options,
  )
  // הבסיס להוק: סוגי הממצאים בלבד, בלי פרטי קשר ובלי הפניות, ולכן בטוח להכניס לריפו.
  writeFileSync(join(dir, BASELINE_FILE), `${JSON.stringify(baselineOf(findings), null, 2)}\n`, 'utf8')
  return result
}

/** בונה, מוסיף מעטפת ושולח. משותף לשליחה הרגילה ולהוק. הרשת נפתחת כאן ורק כאן. */
export async function transmit(
  input: SubmissionInput,
  state: ScanState,
  options: Pick<SendOptions, 'lawyerId' | 'endpoint' | 'runMode' | 'fetchFn' | 'getOidcToken' | 'commit' | 'runId'>,
): Promise<SubmitResponse> {
  const built = buildSubmission(input)
  if (!built.ok) throw new Error(built.errors.join('\n'))

  const endpoint = options.endpoint ?? LAWSTAGER_ENDPOINT_INVENTED
  const lawyerId = options.lawyerId ?? POOL_LAWYER_ID
  const begin = await callFunction<BeginResponse>(options.fetchFn, endpoint, BEGIN_FUNCTION, {
    lawyerId,
    ...(options.getOidcToken ? { oidcToken: await options.getOidcToken('lawstager') } : {}),
  })
  if (begin.consentVersion !== built.submission.consentVersion) throw new Error('נוסח ההסכמה בחבילה אינו הנוסח שהשרת דורש. עדכן את החבילה')

  const envelope = sealSubmission(built.submission, {
    serverPublicKeyPem: begin.serverPublicKeyPem,
    lawyerId,
    nonce: begin.nonce,
    attestation: {
      analyzerVersion: state.analyzerVersion,
      runMode: options.runMode,
      treeDigest: state.treeDigest,
      ...(options.commit ? { commit: options.commit } : {}),
      ...(options.runId ? { runId: options.runId } : {}),
    },
  })
  return callFunction<SubmitResponse>(options.fetchFn, endpoint, SUBMIT_FUNCTION, {
    envelope,
    requestId: randomUUID(),
    ...(options.getOidcToken ? { oidcToken: await options.getOidcToken(`lawstager:${begin.nonce}`) } : {}),
  })
}
