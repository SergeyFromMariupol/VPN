(() => {
  'use strict';

  const packages = __ANDROID_PACKAGES_JSON__;
  const app = document.getElementById('app');
  if (!app) return;
  const subscriptionTitle = window.__SUB_PAGE_DATA__?.subTitle;
  if (typeof subscriptionTitle === 'string' && subscriptionTitle.trim()) {
    document.title = subscriptionTitle.trim();
  }

  function element(tag, className, text) {
    const node = document.createElement(tag);
    node.className = className;
    if (text) node.textContent = text;
    return node;
  }

  function icon(path) {
    const ns = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(ns, 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '1.8');
    svg.setAttribute('stroke-linecap', 'round');
    svg.setAttribute('stroke-linejoin', 'round');
    svg.setAttribute('aria-hidden', 'true');
    const shape = document.createElementNS(ns, 'path');
    shape.setAttribute('d', path);
    svg.append(shape);
    return svg;
  }

  const panel = element('section', 'vpn-app-bypass');
  panel.id = 'android-app-bypass';
  panel.setAttribute('aria-labelledby', 'android-app-bypass-title');
  const top = element('div', 'vpn-app-bypass__top');
  const intro = element('div', 'vpn-app-bypass__intro');
  const badge = element('span', 'vpn-app-bypass__icon');
  badge.append(icon('M12 3l7 3v5c0 4-2.4 7.2-7 10-4.6-2.8-7-6-7-10V6l7-3zM9 12l2 2 4-4'));

  const heading = element('div', 'vpn-app-bypass__heading');
  const title = element('h2', 'vpn-app-bypass__title', 'Приложения, которые ищут VPN');
  title.id = 'android-app-bypass-title';
  const description = element('p', 'vpn-app-bypass__description',
    'Некоторые из этих приложений проверяют, включён ли VPN. Добавьте пакеты в исключения, чтобы их запросы шли с обычного IP.');
  heading.append(title, description);
  intro.append(badge, heading);

  const copy = element('button', 'vpn-app-bypass__copy');
  copy.type = 'button';
  copy.append(icon('M8 7V5a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2h-2M6 9h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2v-8a2 2 0 0 1 2-2z'));
  copy.append(document.createTextNode('Скопировать ' + packages.trimEnd().split('\n').length + ' пакетов'));
  top.append(intro, copy);

  const details = element('details', 'vpn-app-bypass__details');
  const summary = element('summary', 'vpn-app-bypass__summary', 'Показать список');
  const textarea = element('textarea', 'vpn-app-bypass__list');
  textarea.readOnly = true;
  textarea.rows = 7;
  textarea.dir = 'ltr';
  textarea.setAttribute('aria-label', 'Список пакетов приложений Android');
  textarea.value = packages;
  details.append(summary, textarea);
  details.addEventListener('toggle', () => {
    summary.textContent = details.open ? 'Скрыть список' : 'Показать список';
  });

  const status = element('span', 'vpn-app-bypass__status');
  status.setAttribute('role', 'status');
  panel.append(top, details, status);

  copy.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(packages);
      status.textContent = 'Список скопирован';
    } catch {
      details.open = true;
      textarea.focus();
      textarea.select();
      status.textContent = 'Список выделен. Скопируйте его вручную.';
    }
  });

  function placePanel() {
    // The raw feed contains share links. The native sing-box client needs a JSON profile.
    for (const name of app.querySelectorAll('.sub-app-grid .sub-app-name')) {
      if (name.textContent === 'Sing-box') name.closest('.sub-row')?.setAttribute('hidden', '');
    }

    if (panel.isConnected) return;
    const qr = app.querySelector('.sub-tabs .sub-rows > .sub-qr-card');
    if (qr) qr.before(panel);
  }

  new MutationObserver(placePanel).observe(app, { childList: true, subtree: true });
  placePanel();
})();
