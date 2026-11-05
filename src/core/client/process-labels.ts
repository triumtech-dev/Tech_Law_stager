/**
 * תיאור בעברית פשוטה לכל סוג ממצא, להצגה ללקוח לפני השליחה (אפיון v0.2 סעיף 5.1א).
 * מודול טהור. התיאור אומר מה הקוד עושה, לא אם זו הפרה: זו שאלה של עורך הדין.
 */

const EXACT: Readonly<Record<string, string>> = {
  accessibility_statement_link: 'קישור להצהרת נגישות',
  account_deletion: 'מחיקת חשבון משתמש',
  age_gate: 'בדיקת גיל או הסכמת הורה',
  autoplay_media: 'מדיה שמתחילה לנגן מעצמה',
  camera_microphone: 'גישה למצלמה או למיקרופון',
  cancel_flow: 'תהליך ביטול (מנוי או הזמנה)',
  checkbox_prechecked: 'תיבת הסכמה שמסומנת מראש',
  checkout_flow: 'תהליך תשלום או קופה',
  click_on_non_button: 'רכיב שנלחץ בעכבר בלי תמיכה במקלדת',
  confirmshaming: 'ניסוח שמלחיץ משתמש שדוחה הצעה',
  consent_mode: 'הגדרת הסכמה לעוגיות ולמדידה',
  contacts_access: 'גישה לאנשי הקשר של המשתמש',
  content_report: 'דיווח על תוכן או על הפרה',
  cookie_banner: 'באנר עוגיות',
  cookie_library: 'ספרייה לניהול עוגיות',
  cookie_write_client: 'כתיבת עוגיה מדפדפן המשתמש',
  cookie_write_server: 'כתיבת עוגיה מהשרת',
  countdown_pressure: 'טיימר או ספירה לאחור שיוצרים לחץ',
  data_export: 'ייצוא מידע אישי למשתמש',
  device_fingerprint: 'זיהוי המכשיר לפי מאפייניו',
  email_send: 'שליחת מיילים',
  field_address: 'איסוף כתובת מגורים',
  field_birth_date: 'איסוף תאריך לידה',
  field_card: 'איסוף פרטי כרטיס אשראי',
  field_email: 'איסוף כתובת מייל',
  field_file_upload: 'העלאת קבצים על ידי משתמשים',
  field_health: 'איסוף מידע בריאותי',
  field_id_number: 'איסוף מספר זהות',
  field_name: 'איסוף שם',
  field_phone: 'איסוף מספר טלפון',
  geolocation: 'שימוש במיקום המשתמש',
  hidden_decline: 'כפתור דחייה שמוסתר או מוחלש',
  html_without_dir: 'דף בלי הגדרת כיוון כתיבה',
  html_without_lang: 'דף בלי הגדרת שפה',
  img_without_alt: 'תמונה בלי טקסט חלופי',
  indexed_db: 'שמירת מידע במסד נתונים בדפדפן',
  local_storage: 'שמירת מידע באחסון המקומי של הדפדפן',
  marketing_consent_field: 'הסכמה לקבלת דיוור שיווקי',
  negative_tabindex: 'רכיב שהוצא מסדר הניווט במקלדת',
  originality_declaration: 'הצהרת מקוריות על תוכן שמועלה',
  outline_removed: 'הסרת סימון המיקוד במקלדת',
  price_display: 'הצגת מחיר',
  privacy_link: 'קישור למדיניות פרטיות',
  push_permission: 'בקשת הרשאה להתראות',
  recurring_billing: 'חיוב חוזר או מנוי מתחדש',
  refund_flow: 'תהליך החזר כספי',
  shipping: 'משלוח מוצרים',
  signup: 'הרשמת משתמשים',
  sms_send: 'שליחת הודעות SMS',
  social_login: 'התחברות דרך רשת חברתית',
  terms_acceptance: 'אישור תנאי שימוש',
  trial_period: 'תקופת ניסיון',
  unsubscribe: 'הסרה מרשימת דיוור',
  user_generated_post: 'פרסום תוכן על ידי משתמשים',
  user_upload_storage: 'אחסון קבצים שמשתמשים העלו',
  vat_handling: 'טיפול במע"מ',
  whatsapp_link: 'קישור לוואטסאפ',
  zoom_disabled: 'חסימת הגדלה במכשירים ניידים',
}

const SECRET_LABEL = 'ערך סודי (מפתח או סיסמה) שנמצא בקוד. הערך עצמו אינו נשלח'

/** המשפט שמוצג ללקוח לסוג ממצא. סוג שלא מוכר מוצג בשמו הטכני, כדי שלא יוסתר דבר. */
export function describeKind(kind: string): string {
  const exact = EXACT[kind]
  if (exact) return exact
  const [prefix, ...rest] = kind.split(':')
  const tail = rest.join(':')
  switch (prefix) {
    case 'tracker':
      return `טרקר או פיקסל מדידה: ${tail}`
    case 'vendor':
      return `ספק או ספרייה חיצונית: ${tail}`
    case 'host': {
      const [category, ...host] = rest
      return `פנייה לשרת חיצוני (${category ?? 'לא מסווג'}): ${host.join(':')}`
    }
    case 'secret':
      return SECRET_LABEL
    default:
      return `ממצא מסוג ${kind}`
  }
}
