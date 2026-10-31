# Изолированный серверный WARP

Этот модуль создаёт полный TCP/UDP WARP-выход внутри отдельного network
namespace. Default route сервера и прямые VPN-профили сохраняют обычный выход.
При отказе WARP его профили закрываются с ошибкой, без перехода на IP сервера.

Модуль запускает основной установщик после настройки direct-профилей,
Nginx и Certbot. В исходных файлах `@TARGET_IPV4@` и `@TARGET_INTERFACE@` —
параметры: установщик заменяет их только проверенными значениями из inventory.
Нельзя запускать неотрендеренный исходник напрямую.

Порядок: `scripts/install-warp.sh` → установка закреплённых пакетов →
генерация двух независимых connector UUID → namespace/guards/connector →
проверки → payload-watchdog. Каждая фаза имеет собственный rollback snapshot.
При ошибке более поздней фазы успешно завершённые предыдущие фазы сохраняются.
Для `--resume` установщик хранит три root-private checkpoint в
`/var/lib/vpn-installer/warp/`. Возобновление не регистрирует WARP и не создаёт
connector UUID повторно: перед пропуском фазы проверяются версии, digest,
изоляция, live TCP/UDP/DNS и настоящий payload-health. Повреждённый checkpoint
или несовпадение live state останавливают установку.

Xray закреплён на `26.7.28`, Cloudflare WARP — `2026.7.1377.0`.
Официальные URL и SHA-256 находятся в `VERSION.env`; недоступная версия или
несовпадение digest останавливают установку. Смена версии автоматически
не выполняется.

Внутренняя схема:

```text
public Xray → 127.0.0.1:24443 → veth → isolated VLESS → CloudflareWARP → сайт
                                             ↑
                           namespace guard + host guard + UFW
```

Сохранены совместимые внутренние имена `krysyuk-*`, `NL` и `RU bridge`.
Они обозначают роли старого audited connector, а не привязку к стране.
Второй independently authenticated loopback connector `24444` сохраняется
для проверки изоляции credentials; публичные VPN-профили его не используют.
Ни один из этих портов не публикуется в Интернет.

Host `warp-svc.service` маскируется до установки пакета. Отдельный daemon
работает в namespace `krysyuk-warp`, Xray connector — от UID `xraywarp`.
Namespace guard разрешает этому UID только WARP, loopback и ответы в veth.
Host nftables и UFW независимо пропускают только encrypted outer transport
с фиксированным внутренним DSCP/mark. Прочий veth-трафик блокируется.

Состояние и connector UUID хранятся только в root-private файлах
`/etc/krysyuk-warp-egress/` и `/var/lib/krysyuk-warp-egress-warp/`.
Файлы examples пустые; установка каждый раз создаёт новые credentials.
Проверки выводят только `warp=on` и результаты классификации, без WARP IP.

Watchdog проверяет HTTPS payload после каждого цикла с интервалом 15 секунд.
Нужен HTTP 204 от Cloudflare и от gstatic либо google.com. После трёх отказов
пересоздаётся только WARP-контур, с recovery cooldown 120 секунд. Direct Xray
и маршруты основного namespace при этом не перезапускаются и не меняются.

Проверки `test-smoke.sh`, `test-main-route-isolation.sh`, `test-e2e-local.sh`,
`test-invalid.sh` и `test-leak-physical.sh` входят в deploy. TCP/UDP DNS и QUIC
проверяются реальными запросами. Negative tests для потери WARP и guards
находятся в `tests/` и требуют `I_UNDERSTAND_DISRUPTIVE=YES`; они временно
останавливают WARP и автоматически восстанавливают его. Не запускать их
параллельно с watchdog. Тест после reboot требует новый настоящий boot ID.

Этот модуль основан на существующем коде данного проекта. Исторические
проверки серверов не являются приёмкой новой установки. Клиентские скорость,
mobile import и доступность у конкретного провайдера проверяются отдельно.

Официальные источники:

- [Cloudflare Linux packages](https://pkg.cloudflareclient.com/)
- [Cloudflare client modes](https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/configure/modes/)
- [Xray releases](https://github.com/XTLS/Xray-core/releases)
