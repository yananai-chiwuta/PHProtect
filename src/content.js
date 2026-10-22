// PHProtect content fingerprints: CMS markers in the HTML (read-only).
// Runs at document_idle in the top frame only. Never fetches: it reads one
// HTML snapshot and a handful of attributes that are already in the DOM.
(() => {
  const cms = new Set();
  const generatorEl = document.querySelector('meta[name="generator" i]');
  const generator = generatorEl ? generatorEl.getAttribute("content") || "" : "";
  const html = (document.documentElement.innerHTML || "").slice(0, 20000);
  const urls = [...document.querySelectorAll("script[src], link[href]")].map(
    (el) => el.getAttribute("src") || el.getAttribute("href") || ""
  );

  if (/wordpress/i.test(generator)) cms.add("WordPress");
  if (/magento/i.test(generator)) cms.add("Magento");
  if (/drupal/i.test(generator)) cms.add("Drupal");
  if (/joomla/i.test(generator)) cms.add("Joomla");
  if (/laravel/i.test(generator)) cms.add("Laravel");

  if (/\/wp-(content|includes|json)\//i.test(html)) cms.add("WordPress");
  if (urls.some((s) => /\/wp-(content|includes|json)\//i.test(s))) cms.add("WordPress");
  if (urls.some((s) => /\/static\/version\d+\/|\/mage\/|\/skin\/frontend\//i.test(s)))
    cms.add("Magento");
  if (document.querySelector('script[type="text/x-magento-init"]')) cms.add("Magento");
  if (
    urls.some((s) => /\/sites\/default\/files\/|\/core\/misc\/drupal\.js/i.test(s)) ||
    document.querySelector('script[data-drupal-selector], script[src*="/modules/contrib/"]')
  )
    cms.add("Drupal");
  if (urls.some((s) => /\/media\/system\/js\/|\/components\/com_/i.test(s))) cms.add("Joomla");
  if (/\blaravel_session\s*=/i.test(document.cookie)) cms.add("Laravel");

  if (!cms.size && !generator) return;
  try {
    chrome.runtime.sendMessage(
      { type: "cms-hints", cms: [...cms], generator: generator.slice(0, 80) },
      () => {}
    );
  } catch {
    /* extension reloaded */
  }
})();
