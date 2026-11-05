/**
 * כללים לעוגיות, לאחסון בדפדפן, לאיסוף מידע אישי בטפסים ולמנגנוני הסכמה.
 * כל כלל מזהה סימן בקוד בלבד. מה שנטען בפועל בדפדפן נבדק בסריקת האתר החי (שלב R6).
 */

import { CODE_EXTENSIONS, TAG_BODY, UI_EXTENSIONS, type Rule } from './rules'

const UI = UI_EXTENSIONS
const CODE = CODE_EXTENSIONS

export const COOKIE_STORAGE_RULES: readonly Rule[] = [
  { kind: 'cookie_write_client', processType: 'cookies_storage', pattern: /document\.cookie\s*=[^=]/g, confidence: 'high', extensions: UI },
  { kind: 'cookie_write_server', processType: 'cookies_storage', pattern: /\bSet-Cookie\b|\bres\.cookie\s*\(|\bcookies\(\)\.set\s*\(|\bsetcookie\s*\(|\bset_cookie\s*\(/gi, confidence: 'high', extensions: CODE },
  { kind: 'cookie_library', processType: 'cookies_storage', pattern: /\b(?:Cookies|cookies)\.set\s*\(|\bsetCookie\s*\(|\bnookies\.set\s*\(/g, confidence: 'medium', extensions: CODE },
  { kind: 'local_storage', processType: 'cookies_storage', pattern: /\b(?:localStorage|sessionStorage)\.setItem\s*\(|\b(?:localStorage|sessionStorage)\[[^\]]+\]\s*=[^=]/g, confidence: 'high', extensions: UI },
  { kind: 'indexed_db', processType: 'cookies_storage', pattern: /\bindexedDB\.open\s*\(/g, confidence: 'medium', extensions: UI },
  { kind: 'device_fingerprint', processType: 'cookies_storage', pattern: /\bfingerprintjs\b|\bFingerprintJS\b|\bcanvas\.toDataURL\s*\(/g, confidence: 'low', extensions: UI },
]

/**
 * שדות קלט לפי סוג המידע: כל הכללים מתאימים את אותה תגית, וסוג השדה נבדק ב-`accept` לפי `type`, `name`, `id`
 * או `autocomplete`. ⭐ `TAG_BODY` מסתיים ב-`>?`, ולכן תגית שלא נסגרת לא גורמת ל-backtracking (Gate A, סבב 3).
 */
const FIELD_TAG = new RegExp(`<(?:input|textarea|select|Input|TextField)\\b${TAG_BODY}`, 'g')
const field = (names: string): Pick<Rule, 'pattern' | 'accept'> => {
  const attr = new RegExp(`\\b(?:name|id|autoComplete|autocomplete|type)\\s{0,5}=\\s{0,5}["'{]\\s{0,5}["']?(?:${names})\\b`)
  return { pattern: FIELD_TAG, accept: (t) => attr.test(t) }
}

/** תיבה מסומנת מראש: `defaultChecked` שאינו `{false}`, או `checked` קבוע (לא קשור למשתנה). נבדק בקוד ולא בתבנית. */
function isPrechecked(tag: string): boolean {
  if (!/type\s{0,5}=\s{0,5}["'{]\s{0,5}["']?checkbox|<Checkbox\b/.test(tag)) return false
  if (/\bdefaultChecked\b(?!\s{0,5}=\s{0,5}\{\s{0,5}false\s{0,5}\})/.test(tag)) return true
  return /\bchecked\b(?!\s{0,5}=)|\bchecked\s{0,5}=\s{0,5}(?:\{\s{0,5}true\s{0,5}\}|["']?checked["']?|["']true["'])/.test(tag)
}

export const PERSONAL_DATA_RULES: readonly Rule[] = [
  { kind: 'field_email', processType: 'personal_data', ...field('email|e-mail|mail'), confidence: 'high', extensions: UI },
  { kind: 'field_phone', processType: 'personal_data', ...field('tel|phone|mobile|telephone|cellphone'), confidence: 'high', extensions: UI },
  { kind: 'field_id_number', processType: 'personal_data', ...field('id_?number|idNumber|teudat|tz|national_?id|ssn|passport'), confidence: 'high', extensions: UI },
  { kind: 'field_address', processType: 'personal_data', ...field('address|street|city|zip|postal|street-address|address-line1'), confidence: 'high', extensions: UI },
  { kind: 'field_birth_date', processType: 'personal_data', ...field('birth|dob|bday|birthday|birthdate'), confidence: 'high', extensions: UI },
  { kind: 'field_name', processType: 'personal_data', ...field('name|fullName|full_name|firstName|first_name|lastName|last_name|given-name|family-name'), confidence: 'medium', extensions: UI },
  { kind: 'field_card', processType: 'payments', ...field('cc-number|cardNumber|card_number|cc-csc|cvv|cvc'), confidence: 'high', extensions: UI },
  { kind: 'field_health', processType: 'personal_data', ...field('health|medical|diagnosis|allerg|medication|disability'), confidence: 'medium', extensions: UI },
  { kind: 'field_file_upload', processType: 'user_content', ...field('file'), confidence: 'high', extensions: UI },
  { kind: 'geolocation', processType: 'personal_data', pattern: /navigator\.geolocation\.(?:getCurrentPosition|watchPosition)\s*\(/g, confidence: 'high', extensions: UI },
  { kind: 'camera_microphone', processType: 'personal_data', pattern: /navigator\.mediaDevices\.getUserMedia\s*\(/g, confidence: 'high', extensions: UI },
  { kind: 'contacts_access', processType: 'personal_data', pattern: /navigator\.contacts\.select\s*\(/g, confidence: 'high', extensions: UI },
]

export const CONSENT_RULES: readonly Rule[] = [
  {
    kind: 'checkbox_prechecked',
    processType: 'dark_pattern',
    pattern: new RegExp(`<(?:input|Checkbox|Input)\\b${TAG_BODY}`, 'g'),
    accept: isPrechecked,
    confidence: 'medium',
    extensions: UI,
  },
  { kind: 'marketing_consent_field', processType: 'marketing', pattern: /\b(?:newsletter|marketing|promotions?|subscribe|optIn|opt_in|acceptMarketing)\b|דיוור|ניוזלטר|עדכונים\s+ומבצעים/gi, confidence: 'low', extensions: UI },
  { kind: 'terms_acceptance', processType: 'distance_sale', pattern: /\b(?:acceptTerms|agreeTerms|termsAccepted|tosAccepted|terms_accepted|agree_to_terms)\b|(?:אני\s+)?(?:מסכימ|מאשר)[^<>{}\n]{0,30}(?:תנאי\s+השימוש|התקנון)/gi, confidence: 'medium', extensions: UI },
  { kind: 'privacy_link', processType: 'personal_data', pattern: /href\s{0,5}=\s{0,5}["'{][^"'}\n]{0,200}(?:privacy|פרטיות)[^"'}\n]{0,200}["'}]/gi, confidence: 'medium', extensions: UI },
  { kind: 'cookie_banner', processType: 'cookies_storage', pattern: /\b(?:CookieConsent|cookieconsent|CookieBanner|cookie-banner|cookiebot|onetrust|klaro|iubenda|usercentrics|complianz)\b|(?:באנר|הודעת)\s+עוגיות/gi, confidence: 'medium', extensions: UI },
  { kind: 'consent_mode', processType: 'cookies_storage', pattern: /gtag\s*\(\s*["']consent["']/g, confidence: 'high', extensions: UI },
]
