/**
 * סימני נגישות שאפשר לראות בקוד (ת"י 5568 נשען על WCAG). הבדיקה המלאה היא axe על האתר החי (שלב R6).
 * כאן רק מה שהקוד מראה בוודאות סבירה: תמונה בלי `alt`, שפה וכיווניות חסרות, ופעולות שאינן נגישות במקלדת.
 * ⛔ כל תבנית על תגית חסומה ל-`TAG_BODY`, והתנאים על התכונות נבדקים ב-`accept` (Gate A, ReDoS).
 */

import { TAG_BODY, UI_EXTENSIONS, type Rule } from './rules'

const MARKUP = ['jsx', 'tsx', 'vue', 'svelte', 'astro', 'html', 'htm', 'php'] as const
const STYLES = [...UI_EXTENSIONS, 'css', 'scss', 'sass', 'less'] as const
const tag = (names: string): RegExp => new RegExp(`<(?:${names})\\b${TAG_BODY}`, 'g')

export const A11Y_RULES: readonly Rule[] = [
  { kind: 'img_without_alt', processType: 'accessibility', pattern: tag('img|Image'), accept: (t) => !/\balt\s{0,5}=/.test(t), confidence: 'high', extensions: MARKUP },
  {
    kind: 'click_on_non_button',
    processType: 'accessibility',
    pattern: tag('div|span|li|img'),
    accept: (t) => /\b(?:onClick|@click|v-on:click|onclick)\s{0,5}=/.test(t) && !/\b(?:role|tabIndex|tabindex|onKeyDown|onKeyUp|onKeyPress|@keydown)\s{0,5}=/.test(t),
    confidence: 'medium',
    extensions: MARKUP,
  },
  { kind: 'negative_tabindex', processType: 'accessibility', pattern: /\btab[Ii]ndex\s{0,5}=\s{0,5}["'{]\s{0,5}-1\b/g, confidence: 'low', extensions: MARKUP },
  { kind: 'outline_removed', processType: 'accessibility', pattern: /\boutline\s{0,5}:\s{0,5}(?:none|0)\b|\boutline-none\b/g, confidence: 'low', extensions: STYLES },
  { kind: 'autoplay_media', processType: 'accessibility', pattern: tag('video|audio'), accept: (t) => /\bautoplay\b/i.test(t), confidence: 'medium', extensions: MARKUP },
  { kind: 'zoom_disabled', processType: 'accessibility', pattern: /user-scalable\s{0,3}=\s{0,3}(?:no|0)|maximum-scale\s{0,3}=\s{0,3}1(?:\.0)?\b/g, confidence: 'high', extensions: MARKUP },
  { kind: 'accessibility_statement_link', processType: 'accessibility', pattern: /href\s{0,5}=\s{0,5}["'{][^"'}\n]{0,200}(?:accessibility|נגישות)[^"'}\n]{0,200}["'}]/gi, confidence: 'medium', extensions: MARKUP },
]

/** קובץ שורש של מסמך (`<html>`) בלי `lang` או בלי `dir`. נבדק בנפרד כי הוא תכונה של הקובץ ולא של שורה. */
export const HTML_ROOT = /<html\b([^>]{0,600})>?/gi
