(() => {
  'use strict';

  const packages = __ANDROID_PACKAGES_JSON__;
  const app = document.getElementById('app');
  if (!app) return;

  const panel = document.createElement('section');
  panel.id = 'android-app-bypass';
  panel.className = 'sub-row';
  panel.style.flexWrap = 'wrap';

  const main = document.createElement('div');
  main.className = 'sub-row-main';
  const title = document.createElement('div');
  title.className = 'sub-row-title';
  title.textContent = 'Приложения, которые ищут VPN';
  title.style.whiteSpace = 'normal';
  const description = document.createElement('div');
  description.className = 'sub-muted';
  description.textContent = 'По данным RKS Global, некоторые приложения отправляют статус VPN на серверы разработчиков. Добавьте пакеты в исключения, чтобы их трафик шёл напрямую, без IP VPN-сервера.';
  const status = document.createElement('div');
  status.className = 'sub-muted';
  status.setAttribute('role', 'status');
  main.append(title, description, status);

  const copy = document.createElement('button');
  copy.type = 'button';
  copy.className = 'ant-btn ant-btn-default';
  copy.style.whiteSpace = 'normal';
  copy.textContent = 'Скопировать ' + packages.trimEnd().split('\n').length + ' пакетов';

  const details = document.createElement('details');
  details.style.flexBasis = '100%';
  const summary = document.createElement('summary');
  summary.textContent = 'Показать список';
  const textarea = document.createElement('textarea');
  textarea.readOnly = true;
  textarea.rows = 6;
  textarea.dir = 'ltr';
  textarea.style.width = '100%';
  textarea.style.boxSizing = 'border-box';
  textarea.className = 'ant-input';
  textarea.setAttribute('aria-label', 'Список пакетов приложений Android');
  textarea.value = packages;
  details.append(summary, textarea);
  panel.append(main, copy, details);

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
    if (panel.isConnected) return;
    const qr = app.querySelector('.sub-tabs .sub-rows > .sub-qr-card');
    if (qr) qr.before(panel);
  }

  new MutationObserver(placePanel).observe(app, { childList: true, subtree: true });
  placePanel();
})();
