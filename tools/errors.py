#!/usr/bin/env python3
"""Explain installer failures without copying private log text to the terminal.

Classification and rendering are pure. The CLI only reads bounded, private
regular files; it never changes services, packages, certificates or checkpoints.
"""
import argparse
from datetime import datetime, timezone
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import sys


STAGES = {
    'startup': 'Запуск установщика',
    'download': 'Загрузка установщика',
    'source': 'Проверка исходников',
    'preflight': 'Проверка сервера',
    'bootstrap': 'Сохранение настроек установки',
    'base': 'Подготовка Ubuntu',
    'certbot': 'Подготовка HTTPS',
    'tls': 'Сертификат TLS',
    'direct': 'Прямые профили',
    'panel': 'Панель управления',
    'nginx-restart': 'Настройка Nginx',
    'cert-reconcile': 'Обновление сертификатов',
    'warp': 'Cloudflare WARP',
    'dual': 'Профили VPN',
    'xhttp': 'Транспорт XHTTP',
    'renewal': 'Проверка продления TLS',
    'verify': 'Итоговая проверка',
}
PHASES = tuple(STAGES)[5:]
EARLY_STAGES = frozenset(('startup', 'download', 'source', 'preflight', 'bootstrap'))
MAX_LOG_BYTES = 8 * 1024 * 1024
LAUNCH = 'bash <(curl -fsSL https://raw.githubusercontent.com/SergeyFromMariupol/VPN/main/install.sh)'


def _issue(code, title, cause, solution, resume=False, retry_after_utc=None):
    result = dict(code=code, title=title, cause=cause, solution=solution, resume=resume)
    if retry_after_utc:
        result['retry_after_utc'] = retry_after_utc
    return result


# Fixed codes name checks whose quiet shell failure would otherwise be ambiguous.
# Values and command arguments from those checks are deliberately not displayed.
FIXED = {
    'OS_UNSUPPORTED': (
        'Операционная система не подходит.',
        'Нужна Ubuntu 24.04 LTS с архитектурой amd64.',
        'Выберите у провайдера образ Ubuntu 24.04 LTS amd64 и новый чистый VPS.'),
    'ROOT_REQUIRED': (
        'Недостаточно прав для установки.',
        'Установщик запущен не от root.',
        'Войдите в консоль сервера от root и выполните полную команду запуска.'),
    'COMMAND_MISSING': (
        'Не найдена обязательная системная команда.',
        'В образе Ubuntu отсутствует одна из утилит начальной проверки.',
        'Проверьте полноту образа Ubuntu 24.04. Установщик не сможет безопасно продолжить без системных зависимостей.'),
    'NO_SYSTEMD': (
        'Недоступен systemd.',
        'Этот установщик управляет VPN через systemd и не поддерживает такой контейнер или образ.',
        'Используйте полноценный VPS/VM с Ubuntu 24.04 и работающим systemd.'),
    'INSTALL_BUSY': (
        'Другая установка уже выполняется.',
        'Не удалось получить блокировку установщика.',
        'Дождитесь завершения первого запуска. Не запускайте несколько установок одновременно и не удаляйте файл блокировки.'),
    'SOURCE_INTEGRITY': (
        'Проверка целостности исходников не пройдена.',
        'Файлы не совпадают с проверенным манифестом или имеют небезопасные права.',
        'Не обходите проверку хешей и не подменяйте версии. Сохраните состояние и проверьте источник загрузки.'),
    'SOURCE_DOWNLOAD': (
        'Не удалось загрузить проверенный выпуск установщика.',
        'Загрузка официального архива не завершилась успешно.',
        'Проверьте исходящий доступ сервера к GitHub и DNS. Повторите загрузку после восстановления связи.'),
    'BOOTSTRAP_RECOVERY': (
        'Не удалось подтвердить восстановление начального состояния.',
        'Очистка незавершённой подготовки обнаружила изменённые или чужие файлы.',
        'Сохраните файлы и снимки. Не удаляйте каталоги установки вручную и не запускайте установку повторно до диагностики.'),
    'STATE_UNSAFE': (
        'Состояние установки не прошло проверку безопасности.',
        'Права, владелец, ссылки или отметки завершения не соответствуют ожидаемому состоянию.',
        'Сохраните файлы и снимки. Не удаляйте отметки этапов и не исправляйте права вслепую; сначала выполните диагностику.'),
    'NTP_UNSYNCED': (
        'Время сервера ещё не синхронизировано.',
        'Без правильного времени нельзя надёжно проверить TLS и выпустить сертификат.',
        'Дождитесь синхронизации NTP и проверьте время сервера. После синхронизации повторите запуск.'),
    'HOST_NOT_CLEAN': (
        'На сервере обнаружены существующие службы или настройки.',
        'Установка поверх неизвестных VPN, веб-сервера, сертификатов или firewall может повредить их работу.',
        'Используйте отдельный чистый VPS либо сначала разберите существующую конфигурацию. Не удаляйте службы и firewall вслепую.'),
    'SNI_INVALID': (
        'Выбранный REALITY SNI не прошёл проверку.',
        'Нужно DNS-имя подходящего сайта с доверенным TLS 1.3, HTTP/2 и сертификатом на это имя.',
        'Вернитесь к выбору SNI и укажите другой подходящий сайт. Cloudflare для REALITY SNI не используется.'),
    'ACME_IP_ADDRESS': (
        'Адрес сервера не прошёл проверку перед выпуском сертификата.',
        'Выбранный интерфейс не содержит ровно тот глобальный IPv4, который сохранён в настройках.',
        'Проверьте адреса сетевых интерфейсов и настройки VPS у провайдера. При нескольких адресах нужна отдельная проверка конфигурации.'),
    'ACME_XUI_STATE': (
        'Панель не готова к первичному выпуску сертификата.',
        'Служба x-ui должна быть включена, но остановлена на этом этапе.',
        'Проверьте состояние службы. Не останавливайте неизвестные службы вслепую; сначала выясните причину её запуска.'),
    'ACME_DATABASE_STATE': (
        'База панели не соответствует состоянию новой установки.',
        'Перед выпуском сертификата база должна быть исправна и не содержать готовых подключений.',
        'Сохраните базу и снимки. Не удаляйте подключения вручную; проверьте, не осталась ли другая установка.'),
    'ACME_DNS_A': (
        'DNS домена не указывает однозначно на этот сервер.',
        'Проверка A-записи выбранного домена не пройдена.',
        'Укажите одну A-запись на IPv4 этого VPS, отключите DNS-проксирование и дождитесь обновления DNS. Не используйте CNAME вместо требуемой A-записи.'),
    'ACME_DNS_AAAA': (
        'Для домена обнаружена неподдерживаемая IPv6-запись или ошибка DNS.',
        'Первичная установка ожидает отсутствие AAAA-записи.',
        'Удалите AAAA-запись выбранного домена и дождитесь обновления DNS. IPv6 требует отдельной проверки.'),
    'ACME_PORT80': (
        'Порт TCP/80 занят.',
        'Временный HTTP-сервер проверки сертификата не сможет занять порт.',
        'Выясните, какой службе принадлежит порт. Не завершайте неизвестный процесс; согласуйте освобождение порта или выберите чистый VPS.'),
    'ACME_LOCK': (
        'Выпуск сертификата заблокирован.',
        'Блокировка ACME занята либо её файл не прошёл проверку безопасности.',
        'Дождитесь окончания другого выпуска и проверьте состояние установки. Не удаляйте файл блокировки вручную.'),
    'ACME_TIMER': (
        'Служба автоматического продления не готова.',
        'Таймер Certbot должен быть включён и активен.',
        'Проверьте состояние certbot.timer и причину его ошибки. После исправления повторите установку.'),
    'ACME_RENEWAL_BUSY': (
        'Продление сертификата ещё выполняется.',
        'Служба certbot.service не перешла в остановленное состояние.',
        'Дождитесь окончания продления и проверьте состояние службы. Не запускайте два выпуска одновременно.'),
    'ACME_IDENTITY': (
        'Неверно выбрана цель сертификата.',
        'Сохранённый режим IP/домена не соответствует адресу сертификата.',
        'Проверьте сохранённые настройки установки. Не подменяйте адрес готовой подписки или сертификата вручную.'),
    'ACME_CONTACT': (
        'Контакт ACME имеет неверный формат.',
        'Сохранённое значение email не прошло проверку.',
        'Проверьте сохранённые настройки. Пустой email поддерживается; произвольный чужой адрес не исправляет ошибки ACME.'),
    'ACME_EXISTING_CERT': (
        'Уже существует сертификат с этим именем.',
        'Новая установка не должна перезаписывать чужую или ранее созданную цепочку сертификатов.',
        'Сохраните существующий сертификат и ключ. Выполните диагностику перед продолжением или переносом сертификата.'),
    'ACME_CERT_VERIFY': (
        'Полученный сертификат не прошёл проверку.',
        'Не подтверждены срок действия, доверенная цепочка, адрес сертификата или соответствие ключу.',
        'Проверьте время сервера и состояние сертификата. Не отключайте проверку TLS и не подменяйте сертификат самоподписанным автоматически.'),
    'VERIFY_SERVICE': (
        'Проверка служб VPN не пройдена.',
        'Одна из обязательных служб или таймеров не активна либо не включена для запуска.',
        'Посмотрите состояние служб и устраните причину их остановки, затем повторите проверку VPN.'),
    'VERIFY_DATABASE': (
        'Проверка базы панели не пройдена.',
        'SQLite не подтвердил целостность базы.',
        'Сохраните базу и защищённые снимки. Не редактируйте и не удаляйте базу вручную; требуется диагностика восстановления.'),
    'VERIFY_USER': (
        'Панель работает с неожиданными правами.',
        'Процесс панели должен работать от отдельного непривилегированного пользователя.',
        'Проверьте настройки службы и её защитные параметры. Не запускайте панель от root для обхода ошибки.'),
    'VERIFY_NGINX': (
        'Проверка конфигурации Nginx не пройдена.',
        'Nginx не принял текущую конфигурацию.',
        'Проверьте конфигурацию Nginx и пути сертификатов. Не отключайте проверку конфигурации перед перезапуском.'),
    'VERIFY_DNS': (
        'DNS больше не соответствует установленному VPN.',
        'Адреса выбранного домена не совпадают с ожидаемой конфигурацией.',
        'Восстановите одну A-запись на IPv4 этого VPS, отключите DNS-проксирование и удалите неподдерживаемую AAAA-запись.'),
    'VERIFY_CERT': (
        'Сертификат не прошёл итоговую проверку.',
        'Не подтверждён достаточный оставшийся срок действия сертификата.',
        'Проверьте время и автоматическое продление Certbot. Не отключайте проверку срока сертификата.'),
}
FIXED_RESUMABLE = frozenset((
    'INSTALL_BUSY', 'SOURCE_DOWNLOAD', 'ACME_DNS_A', 'ACME_DNS_AAAA',
    'ACME_PORT80', 'ACME_TIMER', 'ACME_RENEWAL_BUSY', 'VERIFY_SERVICE',
    'VERIFY_NGINX', 'VERIFY_DNS', 'VERIFY_CERT', 'NTP_UNSYNCED', 'SNI_INVALID',
))


def _retry_after(text):
    candidates = re.findall(
        r'retry\s+after\s+(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\s+UTC|Z|\+00:00))',
        text, flags=re.I)
    for value in candidates:
        try:
            normalized = re.sub(r'\s+UTC$', '+00:00', value, flags=re.I).replace('Z', '+00:00')
            parsed = datetime.fromisoformat(normalized)
            if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
                continue
            return parsed.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        except ValueError:
            continue
    return None


def classify(stage, text, status=1, code=''):
    """Return only allowlisted explanations; never return log excerpts."""
    text = text if isinstance(text, str) else ''
    lower = text.lower()
    markers = re.findall(r'^VPN_ERROR_CODE=([A-Z][A-Z0-9_]{1,63})\s*$', text, flags=re.M)
    selected = code if code in FIXED else next((item for item in reversed(markers) if item in FIXED), '')

    recovery = (
        re.search(r'\b[A-Z0-9_]*ROLLBACK_OK=0\b|\bROLLBACK_VERIFIED=0\b', text)
        or re.search(r'\bWARP_[A-Z0-9_]*ROLLBACK_FAILED(?:=|:)', text)
        or re.search(r'\bFRESH_XHTTP_FAILED=ROLLBACK_[A-Z0-9_]+', text)
        or 'BOOTSTRAP_CLEANUP_REFUSED=' in text
        or 'BOOTSTRAP_PUBLISH_CONFLICT=' in text
        or selected == 'BOOTSTRAP_RECOVERY'
        or 'certificate recovery needs the protected snapshot' in lower
    )
    if recovery:
        return _issue('RECOVERY_REQUIRED', 'Восстановление после ошибки не подтверждено.',
                      'Установщик обнаружил ошибку отката или изменённое состояние файлов.',
                      'Сохраните защищённые снимки в /var/backups и выполните диагностику. '
                      'Пока не запускайте установку повторно и не удаляйте её файлы.')
    if ('OS_UPGRADE_INCOMPLETE=1' in text or 'APT_INSTALL_PACKAGE_CHANGES_REMAIN=1' in text):
        return _issue('PACKAGE_STATE', 'Состояние системных пакетов требует проверки.',
                      'Обновление Ubuntu не завершено или после ошибки остались изменения пакетов.',
                      'Сначала выполните безопасную диагностику пакетов. Не запускайте повторную '
                      'установку и не удаляйте блокировки до проверки состояния dpkg.')
    integrity = (
        selected == 'SOURCE_INTEGRITY'
        or 'these packages do not match the hashes' in lower
        or re.search(r'sha256sum:.*(?:FAILED|did NOT match)', text, flags=re.I)
        or 'computed checksum did not match' in lower
        or 'checksum mismatch' in lower
        or 'digest mismatch' in lower
        or 'source manifest' in lower and any(word in lower for word in ('failed', 'not found', 'отсутств', 'не пройд'))
    )
    if integrity:
        title, cause, solution = FIXED['SOURCE_INTEGRITY']
        return _issue('INTEGRITY_FAILED', title, cause, solution)
    unsafe = (
        selected == 'STATE_UNSAFE'
        or 'повреждённая или небезопасная отметка' in lower
        or 'небезопасный журнал этапа' in lower
        or 'отметка этапа' in lower and 'другой операцией' in lower
        or 'unsafe /etc/germanyvpn-target.env' in lower
        or 'unsafe managed' in lower
        or 'unsafe' in lower and any(word in lower for word in ('checkpoint', 'symlink', 'ownership', 'permissions'))
    )
    if unsafe:
        title, cause, solution = FIXED['STATE_UNSAFE']
        return _issue('STATE_UNSAFE', title, cause, solution)
    if not selected:
        if 'server is not clean:' in lower or 'existing ufw saved user rules' in lower:
            selected = 'HOST_NOT_CLEAN'
        elif 'wait for ntp synchronization' in lower:
            selected = 'NTP_UNSYNCED'
        elif any(value in lower for value in ('invalid target_reality_sni', 'reality sni must be a dns hostname',
                                              'cloudflare cannot be used as reality sni',
                                              'reality target must pass trusted tls1.3/h2 hostname validation')):
            selected = 'SNI_INVALID'
    if selected:
        title, cause, solution = FIXED[selected]
        return _issue(selected, title, cause, solution, selected in FIXED_RESUMABLE)

    acme = stage in ('tls', 'renewal', 'certbot')
    if acme and ('too many certificates' in lower and 'exact set' in lower
                 and any(word in lower for word in ('identifiers', 'domains', 'hostnames'))):
        counted = bool(re.search(r'too many certificates\s*\(5\)', lower))
        cause = ('Для того же IP или набора доменных имён уже выдано 5 сертификатов за 7 дней.'
                 if counted else 'Центр сертификации ограничил повторный выпуск для того же IP или набора доменных имён.')
        return _issue('ACME_EXACT_RATE_LIMIT', 'Достигнут лимит повторного выпуска сертификатов.',
                      cause, 'Дождитесь разрешённого времени и продолжите эту установку. '
                      'Пересоздание VPS, смена email и новые попытки не снимают лимит центра сертификации.',
                      True, _retry_after(text))
    if acme and ('ratelimited' in lower or 'rate limit' in lower
                 or 'too many certificates' in lower or 'too many new registrations' in lower):
        return _issue('ACME_RATE_LIMIT', 'Центр сертификации ограничил запросы.',
                      'Сработал лимит ACME; это не обязательно лимит пяти сертификатов.',
                      'Дождитесь времени, указанного центром сертификации. Не повторяйте запросы подряд '
                      'и не меняйте email для обхода ограничения.', True, _retry_after(text))
    if acme and any(value in lower for value in (
            'timeout during connect', 'invalid response from', 'http-01 challenge',
            'some challenges have failed', 'unauthorized')):
        return _issue('ACME_HTTP01', 'Проверка адреса центром сертификации не пройдена.',
                      'Центр сертификации не смог подтвердить HTTP-01 на TCP/80.',
                      'Разрешите входящий TCP/80 в firewall провайдера и сервера. Для домена проверьте '
                      'A-запись и отключите DNS-проксирование. Затем повторите установку.', True)
    if any(value in lower for value in ('remove aaaa', 'aaaa mismatch', 'unexpected aaaa')):
        return _issue('DNS_AAAA', *FIXED['ACME_DNS_AAAA'], True)
    if 'use an exact a record, not cname' in lower or 'cname is not supported' in lower:
        return _issue('DNS_CNAME', 'DNS использует неподдерживаемый CNAME.',
                      'На этом этапе требуется точная A-запись.',
                      'Замените CNAME одной A-записью выбранного домена на IPv4 этого VPS и дождитесь обновления DNS.', True)
    if any(value in lower for value in ('target dns a mismatch', 'dns a mismatch', 'dns failure from')):
        return _issue('DNS_A', *FIXED['ACME_DNS_A'], True)
    if any(value in lower for value in ('address already in use', 'could not bind tcp port 80',
                                        'an e2e test port is already in use')):
        return _issue('PORT_BUSY', 'Нужный сетевой порт занят.',
                      'Служба или проверка VPN не смогла занять требуемый порт.',
                      'Выясните владельца порта и согласуйте освобождение. Не завершайте неизвестные процессы вслепую.', True)
    if any(value in lower for value in ('could not get lock', 'unable to acquire the dpkg frontend lock',
                                        'waiting for cache lock', 'dpkg frontend lock was locked')):
        return _issue('PACKAGE_LOCK', 'Менеджер пакетов занят.',
                      'Обновление или установка пакетов уже выполняется другим процессом.',
                      'Дождитесь завершения фонового обновления Ubuntu. Не удаляйте файлы блокировок и не прерывайте неизвестный процесс.', True)
    if 'другая установка уже выполняется' in lower:
        return _issue('INSTALL_BUSY', *FIXED['INSTALL_BUSY'], True)
    if any(value in lower for value in ('dpkg was interrupted', 'dpkg audit', 'package database is not clean')):
        return _issue('PACKAGE_INTERRUPTED', 'Обнаружено незавершённое изменение пакетов Ubuntu.',
                      'dpkg сообщает о прерванной или несогласованной установке пакетов.',
                      'Сначала выполните диагностику пакетов и проверьте, что фоновое обновление завершилось. '
                      'Не запускайте автоматическое исправление пакетов без проверки результата.')
    if any(value in lower for value in ('no space left on device', 'not enough free space')):
        return _issue('DISK_FULL', 'На сервере недостаточно свободного места.',
                      'Не хватает места на диске или свободных inode.',
                      'Проверьте место и inode. Освободите только проверенные ненужные файлы либо увеличьте диск VPS.', True)
    if any(value in lower for value in ('temporary failure resolving', 'could not resolve host', 'curl: (6)')):
        return _issue('NETWORK_DNS', 'Сервер не смог определить адрес внешнего узла.',
                      'Не сработало DNS-разрешение во время загрузки или проверки.',
                      'Проверьте DNS и исходящую сеть VPS. После восстановления связи повторите установку.', True)
    if any(value in lower for value in ('curl: (60)', 'certificate verify failed', 'certificate verification failed',
                                        'certificate is not yet valid', 'certificate has expired',
                                        'ssl certificate problem')):
        return _issue('TLS_TRUST', 'Доверие к TLS-соединению не подтверждено.',
                      'Не прошла проверка времени или доверенной цепочки сертификата.',
                      'Проверьте UTC/NTP сервера и системные корневые сертификаты. Не используйте curl -k и не отключайте проверку TLS.', True)
    if stage in ('download', 'source', 'base', 'certbot', 'warp') and any(value in lower for value in (
            'curl: (22)', '404 not found', 'http error 404', 'pinned release unavailable')):
        return _issue('SOURCE_UNAVAILABLE', 'Проверенный файл выпуска недоступен.',
                      'Официальный источник не вернул требуемый закреплённый файл.',
                      'Проверьте доступность официального выпуска. Не подставляйте другую версию и не обходите проверку хешей.', True)
    if any(value in lower for value in ('curl: (28)', 'connection timed out', 'operation timed out',
                                        'read operation timed out', 'connection timeout')):
        return _issue('NETWORK_TIMEOUT', 'Внешний узел не ответил вовремя.',
                      'Сетевое соединение или загрузка превысили установленное время ожидания.',
                      'Проверьте исходящую сеть VPS, DNS и ограничения провайдера. После восстановления связи повторите установку.', True)
    if any(value in lower for value in ('host warp-svc must remain inactive', 'main route drift',
                                        'physical-ip leak', 'physical ip leak', 'fail-open',
                                        'host-wide warp', 'warp leaked physical')):
        return _issue('WARP_ISOLATION', 'Изоляция выхода WARP не прошла проверку.',
                      'Обнаружено нарушение сетевого контракта или защиты от выхода через физический IP.',
                      'Сохраните защитные правила и снимки, затем выполните диагностику. Не включайте WARP для всего хоста и не удаляйте защиту.')
    if any(value in lower for value in ('isolated namespace cannot reach the warp registration api',
                                        'isolated warp registration failed', 'isolated warp did not become connected')):
        return _issue('WARP_CONNECTIVITY', 'Изолированный WARP не смог подключиться.',
                      'Не завершилась регистрация или проверка связи отдельного WARP-контура.',
                      'Проверьте исходящий доступ VPS и ограничения провайдера для WARP. Не меняйте основной маршрут сервера.', True)
    if ('subscription' in lower and 'mismatch' in lower
            or 'normalized client count mismatch' in lower
            or 'unexpected public connector' in lower):
        return _issue('SUBSCRIPTION_MISMATCH', 'Подписка не совпадает с конфигурацией VPN.',
                      'Не прошла проверка количества, порядка или параметров опубликованных профилей.',
                      'Не раздавайте непроверенную ссылку и не меняйте ключи вручную. Сохраните состояние и выполните диагностику.')
    if re.search(r'FRESH_XHTTP_FAILED=(?:URI_CLIENT_|PAYLOAD_EGRESS_|SOCKS_)[A-Z0-9_]+', text):
        return _issue('XHTTP_TEST_FAILED', 'Проверка подключения XHTTP не пройдена.',
                      'Клиентская проверка не подтвердила подключение или правильный выход трафика.',
                      'Выполните диагностику служб и сети. Не публикуйте профиль до успешной проверки его фактической ссылки.')
    if status in (129, 130, 143) or 'FRESH_XHTTP_FAILED=INTERRUPTED' in text:
        return _issue('CANCELLED', 'Установка прервана.',
                      'Получен сигнал остановки или закрыт терминал.',
                      'Если вы остановили установку намеренно, продолжите её полной командой ниже. '
                      'После аварийной остановки сначала проверьте диагностику.', True)
    return _issue('UNKNOWN', 'Этап завершился с ошибкой.',
                  'Точная причина автоматически не определена. Название этапа само по себе не доказывает причину.',
                  'Выполните безопасную диагностику и сохраните её вывод для разбора. '
                  'Закрытые журналы и снимки оставьте на сервере; не публикуйте их целиком.')


def _destination(value):
    if (not isinstance(value, str) or len(value) > 4096
            or not PurePosixPath(value).is_absolute()
            or '..' in PurePosixPath(value).parts
            or any(ord(character) < 32 or ord(character) == 127 for character in value)):
        raise ValueError('Unsafe destination')
    return 'bash ' + shlex.quote(value.rstrip('/') + '/install.sh')


def _check_command(stage, issue):
    if issue['code'] in ('ACME_EXACT_RATE_LIMIT', 'ACME_RATE_LIMIT'):
        return None
    if issue['code'] in ('PACKAGE_STATE', 'PACKAGE_INTERRUPTED', 'PACKAGE_LOCK'):
        return 'dpkg --audit'
    if issue['code'] == 'DISK_FULL':
        return 'df -h / /var /run && df -i / /var /run'
    if issue['code'] in ('TLS_TRUST', 'ACME_CERT_VERIFY', 'VERIFY_CERT'):
        return 'timedatectl status'
    if issue['code'] in ('PORT_BUSY', 'ACME_PORT80'):
        return "ss -lnt '( sport = :80 )'"
    units = {
        'certbot': 'certbot.service certbot.timer',
        'tls': 'x-ui.service certbot.service certbot.timer',
        'direct': 'x-ui.service', 'panel': 'nginx.service x-ui.service',
        'nginx-restart': 'nginx.service', 'cert-reconcile': 'vpn-cert-reconcile.service vpn-cert-reconcile.timer',
        'warp': 'krysyuk-warp-netns.service krysyuk-xray-warp-egress.service',
        'dual': 'x-ui.service krysyuk-xray-warp-egress.service',
        'xhttp': 'germanyvpn-xhttp-test.service germanyvpn-xhttp-warp.service',
        'renewal': 'certbot.service certbot.timer',
        'verify': 'x-ui.service nginx.service certbot.timer',
    }
    if stage in units:
        return ('systemctl show -p Id -p ActiveState -p SubState -p Result -p ExecMainStatus '
                + units[stage])
    if stage == 'base':
        return 'dpkg --audit'
    return None


def render(issue, stage, status=1, can_resume=False, destination='/opt/vpn-installer'):
    """Render only classifier-owned strings and a validated timestamp."""
    # Only classifier results belong here. No log snippet is used as a heading,
    # explanation, path or command argument.
    command = _destination(destination)
    label = STAGES.get(stage, 'Неизвестный этап')
    error_code = issue.get('code', 'UNKNOWN')
    allowed = set(FIXED) | {
        'RECOVERY_REQUIRED', 'PACKAGE_STATE', 'INTEGRITY_FAILED', 'ACME_EXACT_RATE_LIMIT',
        'ACME_RATE_LIMIT', 'ACME_HTTP01', 'DNS_AAAA', 'DNS_CNAME', 'DNS_A', 'PORT_BUSY',
        'PACKAGE_LOCK', 'PACKAGE_INTERRUPTED', 'DISK_FULL', 'NETWORK_DNS', 'TLS_TRUST',
        'SOURCE_UNAVAILABLE', 'NETWORK_TIMEOUT', 'WARP_ISOLATION', 'WARP_CONNECTIVITY',
        'SUBSCRIPTION_MISMATCH', 'XHTTP_TEST_FAILED', 'CANCELLED', 'UNKNOWN',
    }
    if error_code not in allowed:
        issue = classify(stage, '', status)
        error_code = issue['code']
    lines = ['', f'ОШИБКА [{error_code}] · {label}', f'Код завершения: {int(status)}',
             'Что произошло: ' + issue['title'], 'Причина: ' + issue['cause'],
             'Как исправить: ' + issue['solution']]
    retry = issue.get('retry_after_utc')
    if retry:
        try:
            parsed = datetime.strptime(retry, '%Y-%m-%dT%H:%M:%SZ')
            lines.append('Повторить не раньше: ' + parsed.strftime('%d.%m.%Y %H:%M:%S UTC') + '.')
        except (TypeError, ValueError):
            retry = None
    if error_code in ('ACME_EXACT_RATE_LIMIT', 'ACME_RATE_LIMIT') and not retry:
        lines.append('Время следующей попытки автоматически не распознано. Сначала уточните срок ограничения.')
    check = _check_command(stage, issue)
    if check:
        lines.extend(('', 'Проверка без изменения настроек — скопируйте команду целиком:', '', check))
    if can_resume:
        if error_code not in ('ACME_EXACT_RATE_LIMIT', 'ACME_RATE_LIMIT') or not retry:
            lines.extend(('', 'Безопасная диагностика — скопируйте команду целиком:', '', command + ' --diagnose'))
        if issue.get('resume') and (error_code not in ('ACME_EXACT_RATE_LIMIT', 'ACME_RATE_LIMIT') or retry):
            instruction = ('После указанного времени и устранения причины скопируйте команду целиком:'
                           if retry else 'После устранения причины скопируйте команду целиком:')
            lines.extend(('', instruction, '', command + ' --resume'))
    elif stage in EARLY_STAGES and issue.get('resume'):
        lines.extend(('', 'После устранения причины запустите установщик полной командой:', '', LAUNCH))
    elif error_code in ('ACME_EXACT_RATE_LIMIT', 'ACME_RATE_LIMIT') and retry:
        lines.append('Сохранённый срок ограничения указан выше; новые запросы до этого срока не помогут.')
    else:
        lines.extend(('', 'Сначала разберите причину по безопасной проверке выше. '
                      'Не удаляйте файлы установки и защищённые снимки.'))
    return '\n'.join(lines) + '\n'


def _read_descriptor(descriptor):
    info = os.fstat(descriptor)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
            or info.st_size > MAX_LOG_BYTES):
        raise ValueError('Unsafe log')
    chunks = []
    remaining = MAX_LOG_BYTES + 1
    while remaining:
        chunk = os.read(descriptor, min(65536, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    if remaining == 0:
        raise ValueError('Oversized log')
    after = os.fstat(descriptor)
    if ((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
        raise ValueError('Log changed during read')
    return b''.join(chunks).decode('utf-8', errors='replace')


def read_private_log(path):
    if not hasattr(os, 'O_NOFOLLOW'):
        raise ValueError('Safe file opening unavailable')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        return _read_descriptor(descriptor)
    finally:
        os.close(descriptor)


def _read_at(directory, name):
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        return _read_descriptor(descriptor)
    finally:
        os.close(descriptor)


def _completed(directory, name):
    try:
        text = _read_at(directory, name + '.done')
        if not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\n', text):
            return False
        return datetime.strptime(text.rstrip('\n'), '%Y-%m-%dT%H:%M:%SZ').strftime('%Y-%m-%dT%H:%M:%SZ\n') == text
    except (OSError, ValueError):
        return False


def diagnose(state='/var/lib/vpn-installer', destination='/opt/vpn-installer'):
    """Read historical stage logs, never assume they belong to a current run."""
    command = _destination(destination)
    if not hasattr(os, 'O_NOFOLLOW'):
        print('Не удалось безопасно открыть состояние установки. Используйте диагностику на Ubuntu 24.04.')
        return 1
    try:
        directory = os.open(state, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        print('Состояние установки отсутствует или небезопасно. Закрытые журналы недоступны.')
        return 1
    try:
        info = os.fstat(directory)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) != 0o700):
            print('Состояние установки не прошло проверку прав. Не исправляйте права и не удаляйте файлы вслепую.')
            return 1
        print('Безопасная диагностика VPN')
        print('Ниже — сохранённые журналы прошлых попыток. Они не доказывают текущую причину или состояние служб.')
        print('Настройки, секреты и исходный текст журналов не выводятся.')
        found = False
        for name in PHASES:
            try:
                text = _read_at(directory, name + '.log')
            except FileNotFoundError:
                continue
            except (OSError, ValueError):
                found = True
                print('\nИсторический журнал: ' + STAGES[name])
                print('Журнал недоступен или не прошёл проверку безопасности; его содержимое не прочитано.')
                continue
            found = True
            print('\nИсторический журнал: ' + STAGES[name])
            if _completed(directory, name):
                print('Есть корректная отметка завершения этапа. Журнал не считается текущей ошибкой.')
                continue
            issue = classify(name, text)
            # A historical classification is evidence for investigation, never
            # an instruction to retry or a claim that rollback is safe now.
            print(render(issue, name, can_resume=False, destination=destination).rstrip())
        if not found:
            print('Сохранённых журналов этапов пока нет.')
        print('\nКоманда повторной безопасной диагностики:\n\n' + command + ' --diagnose')
        return 0
    finally:
        os.close(directory)


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError('Invalid diagnostic arguments')


def main(argv=None):
    parser = _Parser(description='Безопасное пояснение ошибок установщика VPN.')
    parser.add_argument('--stage', choices=tuple(STAGES), default='startup')
    parser.add_argument('--status', type=int, default=1)
    parser.add_argument('--code', default='')
    parser.add_argument('--log')
    parser.add_argument('--can-resume', action='store_true')
    parser.add_argument('--destination', default='/opt/vpn-installer')
    parser.add_argument('--state', default='/var/lib/vpn-installer')
    parser.add_argument('--diagnose', action='store_true')
    try:
        args = parser.parse_args(argv)
        _destination(args.destination)
        if args.diagnose:
            return diagnose(args.state, args.destination)
        text = ''
        log_unavailable = False
        if args.log:
            try:
                text = read_private_log(args.log)
            except (OSError, ValueError):
                log_unavailable = True
        # An unreadable/oversized log may hide a failed rollback. Do not let a
        # lower-priority fixed code or signal status turn that uncertainty into
        # an unconditional retry recommendation.
        issue = (classify(args.stage, '', 1) if log_unavailable else
                 classify(args.stage, text, args.status, args.code))
        print(render(issue, args.stage, args.status, args.can_resume, args.destination), end='')
        return 0
    except (OSError, TypeError, ValueError):
        print('Не удалось прочитать безопасную диагностику. Не удаляйте состояние установки; '
              'проверьте права и сохранённые снимки.')
        return 1


if __name__ == '__main__':
    sys.exit(main())
