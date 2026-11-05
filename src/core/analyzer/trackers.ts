/**
 * טרקרים ופיקסלים בקוד. החתימות מותאמות ממערכת אחות של אותו מפתח.
 * ההתאמה לפי חתימה של הטוען (מארח הסקריפט או קריאת האתחול), ולא לפי שם שמופיע איפשהו.
 * ⛔ מזהה המדידה (`G-…`, `GTM-…`) רגיש לרישיות בכוונה: במימוש קודם `/i` התאים ל-`g-recaptcha` ויצר ממצא פרטיות כוזב.
 */

import { CODE_EXTENSIONS, type Rule } from './rules'

interface TrackerSignature {
  readonly id: string
  readonly signature: RegExp
}

const TRACKERS: readonly TrackerSignature[] = [
  { id: 'google-tag-manager', signature: /googletagmanager\.com\/(?:gtm\.js|ns\.html)|["'=]GTM-[A-Z0-9]{4,}["'&]/g },
  { id: 'google-analytics', signature: /googletagmanager\.com\/gtag\/js|google-analytics\.com\/(?:analytics|ga)\.js|\bgtag\s*\(\s*["']config["']|["'=]G-[A-Z0-9]{6,}["'&]|["'=]UA-\d{4,}-\d+["'&]|\bfirebase\/analytics\b|\bgetAnalytics\s*\(/g },
  { id: 'meta-pixel', signature: /connect\.facebook\.net\/[^"']*\/fbevents\.js|\bfbq\s*\(\s*["']init["']|react-facebook-pixel/gi },
  { id: 'hotjar', signature: /static\.hotjar\.com|\bhj\s*\(\s*["']|@hotjar\/browser/gi },
  { id: 'microsoft-clarity', signature: /clarity\.ms\/tag|\bclarity\s*\(\s*["']|@microsoft\/clarity/gi },
  { id: 'cloudflare-web-analytics', signature: /static\.cloudflareinsights\.com\/beacon/gi },
  { id: 'tiktok-pixel', signature: /analytics\.tiktok\.com|\bttq\.load\s*\(/gi },
  { id: 'linkedin-insight', signature: /snap\.licdn\.com|_linkedin_partner_id/gi },
  { id: 'taboola-outbrain', signature: /cdn\.taboola\.com|widgets\.outbrain\.com/gi },
  { id: 'mixpanel', signature: /\bmixpanel\.init\s*\(|mixpanel-browser/gi },
  { id: 'amplitude', signature: /@amplitude\/analytics-browser|\bamplitude\.init\s*\(/gi },
  { id: 'posthog', signature: /\bposthog\.init\s*\(|posthog-js/gi },
  { id: 'segment', signature: /cdn\.segment\.com|@segment\/analytics-next/gi },
  { id: 'vercel-analytics', signature: /@vercel\/analytics/gi },
  { id: 'session-replay', signature: /logrocket|@fullstory\/browser|\bLogRocket\.init\s*\(/gi },
]

/** כלל לכל טרקר: `tracker:<id>`, תהליך `third_party`, ביטחון גבוה (חתימה ולא שם). */
export const TRACKER_RULES: readonly Rule[] = TRACKERS.map(({ id, signature }) => ({
  kind: `tracker:${id}`,
  processType: 'third_party' as const,
  pattern: signature,
  confidence: 'high' as const,
  extensions: [...CODE_EXTENSIONS, 'json'],
}))
