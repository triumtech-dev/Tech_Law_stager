/**
 * המעטפת האטומה של הממצאים (אפיון v0.2 סעיף 6א). מודול טהור על `node:crypto`: בלי רשת ובלי דיסק.
 *
 * הצפנה היברידית: מפתח AES-256-GCM אקראי לכל מעטפת, עטוף ב-RSA-OAEP (SHA-256) למפתח הציבורי של השרת.
 * ⛔ הלקוח מחזיק רק את המפתח הציבורי ולכן אינו יכול לפתוח את המעטפת. המפתח הפרטי רק בשרת (Secret Manager, R4b).
 * ⭐ ה-AAD קושר את המעטפת למזהה עורך הדין, ל-nonce החד-פעמי ול-hash של הממצאים. מעטפת שהופנתה לעורך דין
 * אחר, הועלתה עם nonce אחר או נערכה אחרי הריצה נכשלת בפתיחה כמו טקסט פגום.
 * אימות המקור (OIDC) והבדיקה שה-nonce לא נוצל נעשים בשרת (R4b), לא כאן.
 */

import { createCipheriv, createDecipheriv, createHash, constants, privateDecrypt, publicEncrypt, randomBytes } from 'node:crypto'

import type { ClientFindingsFile } from '../client-findings'
import type { RepoFile } from '../analyzer/types'

import type { ClientSubmission, RunMode } from './submission'

export const ENVELOPE_VERSION = 1
const IV_BYTES = 12
const KEY_BYTES = 32

/** מה שהשרת מעיד על הריצה ושנקשר למעטפת. בריצה מקומית אין `commit` ו-`runId`. */
export interface RunAttestation {
  readonly analyzerVersion: string
  readonly runMode: RunMode
  readonly commit?: string
  readonly runId?: string
  /** hash של עץ הקבצים שנסרקו, להשוואה בשרת ל-commit (סעיף 6.2). */
  readonly treeDigest: string
}

export interface SealedEnvelope {
  readonly v: typeof ENVELOPE_VERSION
  readonly lawyerId: string
  readonly nonce: string
  readonly findingsHash: string
  readonly attestation: RunAttestation
  /** מפתח ה-AES, עטוף ב-RSA-OAEP, ב-base64. */
  readonly wrappedKey: string
  readonly iv: string
  readonly ciphertext: string
  readonly tag: string
}

export interface SealOptions {
  readonly serverPublicKeyPem: string
  readonly lawyerId: string
  readonly nonce: string
  readonly attestation: RunAttestation
}

export interface OpenExpectation {
  readonly lawyerId: string
  readonly nonce: string
}

/** JSON קנוני: מפתחות ממוינים, כדי שה-hash יהיה יציב. */
export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`
  if (value !== null && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(',')}}`
  }
  return JSON.stringify(value)
}

export function hashFindings(findings: ClientFindingsFile): string {
  return createHash('sha256').update(canonicalJson(findings), 'utf8').digest('hex')
}

/** hash של הנתיבים ושל התוכן של הקבצים שנקראו. התוכן עצמו לא יוצא. */
export function computeTreeDigest(files: readonly RepoFile[]): string {
  const lines = files
    .map((f) => `${f.path}\0${createHash('sha256').update(f.text, 'utf8').digest('hex')}`)
    .sort()
  return createHash('sha256').update(lines.join('\n'), 'utf8').digest('hex')
}

/** ⭐ ה-attestation (גרסת מנתח, מסלול, commit, הרצה, טביעת עץ) נקשר ל-AAD: שינוי בו אחרי החתימה מכשיל את הפתיחה (Gate A). */
function attestationHash(attestation: RunAttestation): string {
  return createHash('sha256').update(canonicalJson(attestation), 'utf8').digest('hex')
}

function aadFor(lawyerId: string, nonce: string, findingsHash: string, attestation: RunAttestation): Buffer {
  for (const part of [lawyerId, nonce, findingsHash]) {
    if (part.length === 0 || part.includes(':')) throw new Error('envelope: רכיב הקשר ריק או כולל נקודתיים')
  }
  return Buffer.from(`lawstager-envelope:v${ENVELOPE_VERSION}:${lawyerId}:${nonce}:${findingsHash}:${attestationHash(attestation)}`, 'utf8')
}

export function sealSubmission(submission: ClientSubmission, options: SealOptions): SealedEnvelope {
  const findingsHash = hashFindings(submission.findings)
  const key = randomBytes(KEY_BYTES)
  const iv = randomBytes(IV_BYTES)
  const cipher = createCipheriv('aes-256-gcm', key, iv)
  cipher.setAAD(aadFor(options.lawyerId, options.nonce, findingsHash, options.attestation))
  const ciphertext = Buffer.concat([cipher.update(canonicalJson(submission), 'utf8'), cipher.final()])
  const wrappedKey = publicEncrypt(
    { key: options.serverPublicKeyPem, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    key,
  )
  return {
    v: ENVELOPE_VERSION,
    lawyerId: options.lawyerId,
    nonce: options.nonce,
    findingsHash,
    attestation: options.attestation,
    wrappedKey: wrappedKey.toString('base64'),
    iv: iv.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
  }
}

/**
 * פתיחה בשרת בלבד. זורק על מעטפת פגומה, ערוכה, שהופנתה לעורך דין אחר או שה-nonce שלה שונה.
 * ⛔ הודעת השגיאה אחידה ואינה נושאת את הקלט (לא לכתוב מעטפת ליומן).
 */
export function openEnvelope(envelope: SealedEnvelope, privateKeyPem: string, expected: OpenExpectation): ClientSubmission {
  const fail = (): never => {
    throw new Error('envelope: פתיחה נכשלה')
  }
  if (envelope.v !== ENVELOPE_VERSION) fail()
  if (envelope.lawyerId !== expected.lawyerId || envelope.nonce !== expected.nonce) fail()
  try {
    const key = privateDecrypt(
      { key: privateKeyPem, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
      Buffer.from(envelope.wrappedKey, 'base64'),
    )
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(envelope.iv, 'base64'))
    decipher.setAAD(aadFor(envelope.lawyerId, envelope.nonce, envelope.findingsHash, envelope.attestation))
    decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'))
    const plain = Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext, 'base64')), decipher.final()]).toString('utf8')
    const submission = JSON.parse(plain) as ClientSubmission
    if (hashFindings(submission.findings) !== envelope.findingsHash) fail()
    return submission
  } catch {
    return fail()
  }
}
