/**
 * התצוגה המקדימה שהלקוח קורא (אפיון v0.2 סעיף 6א.1). טקסט בעברית, ללא חתימה וללא תוקף מול השרת.
 * ⛔ כל המידע כאן מגיע מ-`ClientFindingsFile` בלבד, שאין בו קטעי קוד.
 */

import type { ClientFindingsFile } from '../client-findings'

import { describeKind } from './process-labels'

export const PREVIEW_DISCLAIMER = 'זו תצוגה לקריאה בלבד. אין לה תוקף מול השרת, והדוח מבוסס רק על הקובץ האטום שיישלח.'

export interface ReviewItem {
  readonly kind: string
  readonly description: string
  readonly count: number
  readonly locations: readonly string[]
}

/** הרשימה שהלקוח עובר עליה ומאשר, בעברית פשוטה. */
export function reviewItems(findings: ClientFindingsFile): ReviewItem[] {
  return findings.processes.map((p) => ({
    kind: p.kind,
    description: describeKind(p.kind),
    count: p.count,
    locations: p.references.map((r) => `${r.path}:${r.line}`),
  }))
}

export function renderPreview(findings: ClientFindingsFile): string {
  const items = reviewItems(findings)
  const lines: string[] = ['סיכום הסריקה (לקריאה בלבד)', '', PREVIEW_DISCLAIMER, '']
  if (items.length === 0) lines.push('לא זוהו תהליכים בקוד.')
  items.forEach((item, index) => {
    lines.push(`${index + 1}. ${item.description} (נמצא ${item.count} פעמים)`)
    for (const location of item.locations) lines.push(`   ${location}`)
  })
  const { coverage } = findings
  lines.push('', `כיסוי: נקראו ${coverage.filesRead} קבצים.`)
  if (findings.partialCoverage) lines.push('הכיסוי חלקי: חלק מהקבצים דולגו בגלל גודל או תקרה, והדוח יסומן כך.')
  return lines.join('\n')
}
