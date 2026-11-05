/**
 * ספריות ושירותי צד ג' לפי קובצי התלויות (`package.json`, `requirements.txt`).
 * תלות מוצהרת היא סימן שהמערכת מעבירה מידע לספק, או מאפשרת לו לאסוף. הספק עצמו (מי, לאן) נכנס לטיוטת הפרטיות.
 * ⛔ הקטלוג סגור: חבילה שאינה כאן אינה מסווגת ואינה ממצא. לא מנחשים קטגוריה לפי שם.
 */

import { evidenceFor, makeLocator } from './evidence'
import type { Finding, ProcessType, RepoFile } from './types'

interface VendorEntry {
  /** שם החבילה, או קידומת שמסתיימת ב-`/` למרחב שמות (`@sentry/`). */
  readonly pkg: string
  readonly vendor: string
  readonly processType: ProcessType
}

const VENDORS: readonly VendorEntry[] = [
  // תשלום
  { pkg: 'stripe', vendor: 'stripe', processType: 'payments' },
  { pkg: '@stripe/', vendor: 'stripe', processType: 'payments' },
  { pkg: '@paypal/', vendor: 'paypal', processType: 'payments' },
  { pkg: 'braintree', vendor: 'braintree', processType: 'payments' },
  { pkg: 'braintree-web', vendor: 'braintree', processType: 'payments' },
  // התחברות וזהות
  { pkg: 'next-auth', vendor: 'next-auth', processType: 'account' },
  { pkg: '@auth0/', vendor: 'auth0', processType: 'account' },
  { pkg: '@clerk/', vendor: 'clerk', processType: 'account' },
  { pkg: '@supabase/supabase-js', vendor: 'supabase', processType: 'account' },
  { pkg: 'firebase', vendor: 'firebase', processType: 'third_party' },
  { pkg: 'firebase-admin', vendor: 'firebase', processType: 'third_party' },
  { pkg: 'passport', vendor: 'passport', processType: 'account' },
  // ניטור תקלות והקלטת סשן
  { pkg: '@sentry/', vendor: 'sentry', processType: 'third_party' },
  { pkg: 'sentry-sdk', vendor: 'sentry', processType: 'third_party' },
  { pkg: 'logrocket', vendor: 'logrocket', processType: 'third_party' },
  { pkg: '@fullstory/', vendor: 'fullstory', processType: 'third_party' },
  // אנליטיקה
  { pkg: 'react-ga', vendor: 'google-analytics', processType: 'third_party' },
  { pkg: 'react-ga4', vendor: 'google-analytics', processType: 'third_party' },
  { pkg: 'mixpanel-browser', vendor: 'mixpanel', processType: 'third_party' },
  { pkg: 'mixpanel', vendor: 'mixpanel', processType: 'third_party' },
  { pkg: '@amplitude/', vendor: 'amplitude', processType: 'third_party' },
  { pkg: 'posthog-js', vendor: 'posthog', processType: 'third_party' },
  { pkg: '@segment/', vendor: 'segment', processType: 'third_party' },
  { pkg: '@vercel/analytics', vendor: 'vercel-analytics', processType: 'third_party' },
  { pkg: '@microsoft/clarity', vendor: 'microsoft-clarity', processType: 'third_party' },
  { pkg: '@hotjar/browser', vendor: 'hotjar', processType: 'third_party' },
  { pkg: 'react-facebook-pixel', vendor: 'meta-pixel', processType: 'third_party' },
  // עוגיות והסכמה
  { pkg: 'js-cookie', vendor: 'js-cookie', processType: 'cookies_storage' },
  { pkg: 'universal-cookie', vendor: 'universal-cookie', processType: 'cookies_storage' },
  { pkg: 'react-cookie', vendor: 'react-cookie', processType: 'cookies_storage' },
  { pkg: 'cookies-next', vendor: 'cookies-next', processType: 'cookies_storage' },
  { pkg: 'nookies', vendor: 'nookies', processType: 'cookies_storage' },
  { pkg: 'cookie-parser', vendor: 'cookie-parser', processType: 'cookies_storage' },
  { pkg: 'react-cookie-consent', vendor: 'react-cookie-consent', processType: 'cookies_storage' },
  { pkg: 'vanilla-cookieconsent', vendor: 'cookieconsent', processType: 'cookies_storage' },
  // דיוור, SMS והתראות
  { pkg: 'nodemailer', vendor: 'nodemailer', processType: 'marketing' },
  { pkg: '@sendgrid/mail', vendor: 'sendgrid', processType: 'marketing' },
  { pkg: 'sendgrid', vendor: 'sendgrid', processType: 'marketing' },
  { pkg: '@mailchimp/', vendor: 'mailchimp', processType: 'marketing' },
  { pkg: 'resend', vendor: 'resend', processType: 'marketing' },
  { pkg: 'twilio', vendor: 'twilio', processType: 'marketing' },
  { pkg: 'web-push', vendor: 'web-push', processType: 'notifications' },
  { pkg: 'react-onesignal', vendor: 'onesignal', processType: 'notifications' },
  { pkg: 'expo-notifications', vendor: 'expo-notifications', processType: 'notifications' },
  // העלאת תוכן ואחסון
  { pkg: 'multer', vendor: 'multer', processType: 'user_content' },
  { pkg: 'react-dropzone', vendor: 'react-dropzone', processType: 'user_content' },
  { pkg: '@aws-sdk/client-s3', vendor: 'aws-s3', processType: 'user_content' },
  { pkg: 'cloudinary', vendor: 'cloudinary', processType: 'user_content' },
  { pkg: 'uploadthing', vendor: 'uploadthing', processType: 'user_content' },
  // מפות וצ'אט
  { pkg: '@react-google-maps/api', vendor: 'google-maps', processType: 'third_party' },
  { pkg: 'mapbox-gl', vendor: 'mapbox', processType: 'third_party' },
  { pkg: '@intercom/messenger-js-sdk', vendor: 'intercom', processType: 'third_party' },
  { pkg: 'crisp-sdk-web', vendor: 'crisp', processType: 'third_party' },
  { pkg: '@tawk.to/tawk-messenger-react', vendor: 'tawk', processType: 'third_party' },
  // שירותי AI (מידע של משתמשים שעשוי לעבור לספק מודל)
  { pkg: 'openai', vendor: 'openai', processType: 'third_party' },
  { pkg: '@anthropic-ai/sdk', vendor: 'anthropic', processType: 'third_party' },
  { pkg: 'anthropic', vendor: 'anthropic', processType: 'third_party' },
  { pkg: '@google/genai', vendor: 'google-genai', processType: 'third_party' },
  { pkg: '@google/generative-ai', vendor: 'google-genai', processType: 'third_party' },
  { pkg: '@google-cloud/vertexai', vendor: 'google-vertex', processType: 'third_party' },
]

export function vendorFor(pkg: string): VendorEntry | undefined {
  const name = pkg.trim().toLowerCase()
  return VENDORS.find((v) => (v.pkg.endsWith('/') ? name.startsWith(v.pkg) : name === v.pkg))
}

function fileName(path: string): string {
  return (path.split('/').at(-1) ?? '').toLowerCase()
}

/** שמות התלויות בקובץ, עם מספר השורה שבה כל אחת מופיעה. קובץ שאינו קובץ תלויות: רשימה ריקה. */
export function dependenciesOf(file: RepoFile): { name: string; line: number }[] {
  const name = fileName(file.path)
  const locator = makeLocator(file.text)
  const out: { name: string; line: number }[] = []
  if (name === 'package.json') {
    let parsed: unknown
    try {
      parsed = JSON.parse(file.text)
    } catch {
      return []
    }
    if (typeof parsed !== 'object' || parsed === null) return []
    const record = parsed as Record<string, unknown>
    for (const section of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
      const deps = record[section]
      if (typeof deps !== 'object' || deps === null) continue
      for (const dep of Object.keys(deps)) {
        const at = file.text.indexOf(`"${dep}"`)
        out.push({ name: dep, line: at < 0 ? 1 : locator.lineAt(at) })
      }
    }
    return out
  }
  if (name === 'requirements.txt' || name.endsWith('-requirements.txt')) {
    file.text.split('\n').forEach((raw, i) => {
      const dep = /^\s*([A-Za-z0-9_.-]+)/.exec(raw.replace(/#.*/, ''))?.[1]
      if (dep !== undefined) out.push({ name: dep, line: i + 1 })
    })
  }
  return out
}

/** ממצא `vendor:<vendor>` לכל תלות מוכרת. ספק שמופיע בכמה קבצים מקבל ממצא לכל קובץ. */
export function vendorFindings(file: RepoFile): Finding[] {
  const out: Finding[] = []
  const seen = new Set<string>()
  for (const dep of dependenciesOf(file)) {
    const entry = vendorFor(dep.name)
    if (entry === undefined || seen.has(entry.vendor)) continue
    seen.add(entry.vendor)
    out.push({
      kind: `vendor:${entry.vendor}`,
      processType: entry.processType,
      path: file.path,
      line: dep.line,
      evidence: evidenceFor(dep.name),
      confidence: 'high',
    })
  }
  return out
}
