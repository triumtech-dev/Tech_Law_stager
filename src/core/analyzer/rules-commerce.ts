/**
 * כללים לתשלום ולמנויים, למכירה מרחוק, לתוכן משתמשים, לחשבון, לקטינים, לדיוור ולהתראות,
 * ולדפוסים מטעים. הכללים מזהים שהתהליך קיים בקוד. את החובות שחלות עליו קובע קטלוג החובות (שלב R2).
 */

import { CODE_EXTENSIONS, UI_EXTENSIONS, type Rule } from './rules'

const UI = UI_EXTENSIONS
const CODE = CODE_EXTENSIONS

/** כפתור דחייה שעוצב כמעט בלתי נראה (שקיפות נמוכה או גופן זעיר). נבדק בקוד, כדי שהתבנית תישאר ליניארית. */
function isHiddenDecline(tag: string): boolean {
  if (!/ביטול|לא\s{1,3}תודה|דחייה|\bcancel\b|\bdecline\b|no\s{1,3}thanks/i.test(tag)) return false
  return /opacity\s{0,3}:\s{0,3}0?\.[0-3]|font-?size\s{0,3}:\s{0,3}(?:[0-9]|1[01])px|text-\[(?:[0-9]|1[01])px\]/i.test(tag)
}

export const COMMERCE_RULES: readonly Rule[] = [
  { kind: 'checkout_flow', processType: 'payments', pattern: /\b(?:checkout|createPaymentIntent|paymentIntents\.create|createOrder|placeOrder)\b|תשלום\s+מאובטח|(?<![֐-׿])לתשלום/gi, confidence: 'medium', extensions: CODE },
  { kind: 'recurring_billing', processType: 'subscription', pattern: /\b(?:subscriptions\.create|recurring|auto[_-]?renew|autoRenew|billing_cycle|interval\s*:\s*["'](?:month|year)["'])|הוראת\s+קבע|חידוש\s+אוטומטי|מנוי\s+חודשי/gi, confidence: 'medium', extensions: CODE },
  { kind: 'trial_period', processType: 'subscription', pattern: /\b(?:trial_period_days|trialEnd|free_?trial|trial_end)\b|תקופת\s+ניסיון/gi, confidence: 'medium', extensions: CODE },
  { kind: 'cancel_flow', processType: 'subscription', pattern: /\b(?:cancelSubscription|subscriptions\.(?:cancel|del)|cancel_at_period_end)\b|ביטול\s+(?:מנוי|עסקה|הזמנה)/gi, confidence: 'medium', extensions: CODE },
  { kind: 'refund_flow', processType: 'distance_sale', pattern: /\b(?:refunds\.create|createRefund|refund)\s*\(|החזר\s+כספי|מדיניות\s+(?:החזרות|ביטולים)/gi, confidence: 'medium', extensions: CODE },
  { kind: 'shipping', processType: 'distance_sale', pattern: /\b(?:shipping_?address|shippingAddress|shippingMethod|delivery_?date|deliveryDate)\b|דמי\s+משלוח|מועד\s+(?:אספקה|משלוח)/gi, confidence: 'medium', extensions: CODE },
  { kind: 'price_display', processType: 'distance_sale', pattern: /(?:₪|ש["״]ח|\bILS\b)[ \t]{0,3}\{|\{[^}\n]{0,80}\}[ \t]{0,3}(?:₪|ש["״]ח)|\bIntl\.NumberFormat\([^)]{0,200}currency\s*:\s*["']ILS["']/g, confidence: 'low', extensions: UI },
  { kind: 'vat_handling', processType: 'distance_sale', pattern: /\b(?:vat|VAT_RATE|vatRate|tax_rate)\b|מע["״]מ/g, confidence: 'low', extensions: CODE },
]

export const CONTENT_ACCOUNT_RULES: readonly Rule[] = [
  { kind: 'user_upload_storage', processType: 'user_content', pattern: /\b(?:uploadBytes|uploadBytesResumable|putObject|PutObjectCommand|multer\s*\(|upload\.single|cloudinary\.uploader\.upload)\b/g, confidence: 'high', extensions: CODE },
  { kind: 'user_generated_post', processType: 'user_content', pattern: /\b(?:createPost|addComment|postComment|submitReview|createReview|publishPost)\b/g, confidence: 'medium', extensions: CODE },
  { kind: 'content_report', processType: 'user_content', pattern: /\b(?:reportContent|reportAbuse|flagContent|report_abuse)\b|דיווח\s+על\s+(?:תוכן|הפרה)/gi, confidence: 'medium', extensions: CODE },
  { kind: 'originality_declaration', processType: 'user_content', pattern: /\b(?:ownsRights|originalContent|rightsDeclaration|copyrightConfirm)\b|(?:מצהיר|מאשר)[^<>{}\n]{0,30}(?:זכויות|מקורי)/gi, confidence: 'medium', extensions: UI },
  { kind: 'signup', processType: 'account', pattern: /\b(?:createUserWithEmailAndPassword|signUp|signup|register(?:User)?|auth\.admin\.createUser)\s*\(/g, confidence: 'high', extensions: CODE },
  { kind: 'social_login', processType: 'third_party', pattern: /\b(?:GoogleAuthProvider|FacebookAuthProvider|OAuthProvider|signInWithPopup|signInWithRedirect)\b|\bprovider\s*:\s*["'](?:google|facebook|github|apple)["']/g, confidence: 'high', extensions: CODE },
  { kind: 'account_deletion', processType: 'account', pattern: /\b(?:deleteUser|deleteAccount|delete_account|auth\.admin\.deleteUser)\s*\(|מחיקת\s+(?:חשבון|משתמש)/gi, confidence: 'high', extensions: CODE },
  { kind: 'data_export', processType: 'account', pattern: /\b(?:exportUserData|downloadMyData|export_data|dataExport)\b|ייצוא\s+(?:המידע|נתונים)/gi, confidence: 'medium', extensions: CODE },
  { kind: 'age_gate', processType: 'minors', pattern: /\b(?:ageVerification|verifyAge|isAdult|minAge|min_age|age\s*[<>]=?\s*1[368])\b|מעל\s+גיל\s+1[368]|הסכמת\s+(?:הורה|הורים)|קטינים?/g, confidence: 'medium', extensions: CODE },
]

export const MESSAGING_RULES: readonly Rule[] = [
  { kind: 'email_send', processType: 'marketing', pattern: /\b(?:sendMail|transporter\.sendMail|sgMail\.send|resend\.emails\.send|ses\.sendEmail|SendEmailCommand|mailchimp\.)/g, confidence: 'medium', extensions: CODE },
  { kind: 'sms_send', processType: 'marketing', pattern: /\b(?:twilio|messages\.create\s{0,5}\(\s{0,5}\{[^}]{0,300}\bto\b|sendSms|send_sms|inforu|019sms)/gi, confidence: 'medium', extensions: CODE },
  { kind: 'unsubscribe', processType: 'marketing', pattern: /\bunsubscribe\b|List-Unsubscribe|הסרה\s+מ(?:רשימת|הדיוור)|להסרה/gi, confidence: 'medium', extensions: CODE },
  { kind: 'push_permission', processType: 'notifications', pattern: /\bNotification\.requestPermission\s*\(|\bgetToken\s*\(\s*messaging|\bpushManager\.subscribe\s*\(|\bOneSignal\b/g, confidence: 'high', extensions: UI },
  { kind: 'whatsapp_link', processType: 'marketing', pattern: /\b(?:wa\.me|api\.whatsapp\.com|graph\.facebook\.com\/v\d+\.\d+\/\d+\/messages)\b/g, confidence: 'medium', extensions: CODE },
]

export const DARK_PATTERN_RULES: readonly Rule[] = [
  { kind: 'countdown_pressure', processType: 'dark_pattern', pattern: /\b(?:countdown|CountdownTimer|timeLeft|expiresIn)\b|(?:נשארו|נותרו)[ \t]{1,5}(?:רק[ \t]{1,5})?(?:\{[^}\n]{0,40}\}|\d{1,6})?[ \t]{0,5}(?:דקות|שעות|יחידות|מקומות)|ההצעה[ \t]{1,5}(?:תפוג|נגמרת)/gi, confidence: 'low', extensions: UI },
  { kind: 'confirmshaming', processType: 'dark_pattern', pattern: /(?:לא\s+תודה,?\s+אני\s+(?:לא\s+)?(?:רוצה|אוהב|צריך))|no\s+thanks,?\s+i\s+(?:don'?t|prefer)/gi, confidence: 'medium', extensions: UI },
  { kind: 'hidden_decline', processType: 'dark_pattern', pattern: /<(?:button|a)\b[^>]{0,600}>?[^<]{0,200}/gi, accept: isHiddenDecline, confidence: 'low', extensions: UI },
]
