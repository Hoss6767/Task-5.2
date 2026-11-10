import DOMPurify from 'dompurify';

// Add a hook to sanitize dangerous URL protocols from href attributes
DOMPurify.addHook('afterSanitizeAttributes', (node) => {
  if (node.tagName === 'A' && node.hasAttribute('href')) {
    const href = node.getAttribute('href').trim().toLowerCase();
    if (href.startsWith('javascript:')) {
      node.removeAttribute('href');
    }
  }
});

/**
 * Sanitizes unsafe HTML input strings to prevent Stored XSS attacks.
 * Strips dangerous tags, inline event handlers, and javascript: link protocols.
 */
export const sanitizeHtml = (dirty) => {
  if (!dirty) return '';

  return DOMPurify.sanitize(dirty, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br', 'ul', 'ol', 'li', 'span'],
    ALLOWED_ATTR: ['href', 'title', 'target', 'rel'],
    ALLOWED_URI_REGEXP: /^(?:(?:https?|mailto|ftp):|[^a-z]|[a-z+.\-]+(?:[^:]|$))/i,
  });
};

export default sanitizeHtml;