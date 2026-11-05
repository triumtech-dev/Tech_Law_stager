/**
 * קבועי הסריקה המקומית. תקרות בלבד.
 */

/** קובץ גדול מזה אינו נקרא (נספר בכיסוי כ-`too_large`). */
export const MAX_FILE_BYTES = 1_000_000
/** תקרת הקבצים שנקראים בסריקה אחת. מעבר לה הקבצים נספרים כ-`over_limit`. */
export const MAX_FILES_READ_INVENTED = 50_000
/** אורך קטע הראיה שנשמר, אחרי הסרת סודות. */
export const EVIDENCE_MAX = 200
/** ממצאים לכל סוג ממצא בסריקה. הספירה המלאה נשמרת גם מעבר לתקרה. */
export const MAX_FINDINGS_PER_KIND = 25
/** תקרה כוללת לממצאי מארחים חיצוניים (כל מארח הוא סוג ממצא נפרד). */
export const MAX_HOST_FINDINGS = 200
/** שורה ארוכה מזה בממוצע מסמנת קובץ ממוזער (`minified`). */
export const MINIFIED_AVG_LINE = 400
