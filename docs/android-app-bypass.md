# Исключение Android-приложений из VPN

Исключённые приложения используют обычное подключение устройства. Маршрутизация по доменам и IP применяется отдельно. Профиль этих правил в Happ, INCY и v2RayTun называется так же, как имя, введённое при установке VPN. После изменения списка исключений переподключите VPN. [Документация Android](https://developer.android.com/develop/connectivity/vpn#per-app)

## Список приложений

В [TXT для импорта](../bundle/scripts/android-app-bypass.txt) 45 пакетов для 44 приложений. У Мегамаркета указаны две сборки. При импорте всего файла клиент получит пакеты из всех таблиц.

### Приложения из исследования RKS Global

При повторной проверке 16 апреля 2026 года исследователи обнаружили детекцию VPN во всех 30 приложениях из исходной выборки. В таблице указаны идентификаторы всех APK из исследования и дополнительный пакет Мегамаркета из RuStore. [Перечень APK](https://rks.global/files/research/russian_apps_search_for_vpn_ru.pdf#page=22) · [Повторный анализ](https://rks.global/files/research/russian_apps_search_for_vpn_ru.pdf#page=30) · [Таблица исследования](https://airtable.com/appWkT7FmgHwcP4K1/shr4OxfMOh2kZXH72/tbl4NptrrXE0yf3OB/viwrejZqSFlinGMR7) · [Мегамаркет в RuStore](https://www.rustore.ru/catalog/app/ru.goods.marketplace)

| Приложение | Пакет Android |
| --- | --- |
| Авито | `com.avito.android` |
| Т-Банк | `com.idamob.tinkoff.android` |
| VK Видео | `com.vk.vkvideo` |
| ВКонтакте | `com.vkontakte.android` |
| Wildberries | `com.wildberries.ru` |
| Яндекс Браузер | `com.yandex.browser` |
| Альфа-Банк | `ru.alfabank.mobile.android` |
| Яндекс Маркет | `ru.beru.android` |
| 2ГИС | `ru.dublgis.dgismobile` |
| Яндекс Еда | `ru.foodfox.client` |
| Кинопоиск | `ru.kinopoisk` |
| Почта Mail.ru | `ru.mail.mailapp` |
| МегаФон | `ru.megafon.mlk` |
| Мегамаркет | `ru.megamarket.marketplace` |
| Мой МТС | `ru.mts.mymts` |
| Mir Pay | `ru.nspk.mirpay` |
| Одноклассники | `ru.ok.android` |
| MAX | `ru.oneme.app` |
| Ozon | `ru.ozon.app.android` |
| Госуслуги | `ru.rostel` |
| RUTUBE | `ru.rutube.app` |
| Самокат | `ru.sbcs.store` |
| СберБанк Онлайн | `ru.sberbankmobile` |
| RuStore | `ru.vk.store` |
| ВТБ Онлайн | `ru.vtb24.mobilebanking.android` |
| Яндекс Музыка | `ru.yandex.music` |
| Яндекс Go | `ru.yandex.taxi` |
| Яндекс Карты | `ru.yandex.yandexmaps` |
| Дзен | `ru.zen.android` |
| VK Музыка | `com.uma.musicvk` |
| Мегамаркет, другая сборка | `ru.goods.marketplace` |

### Другие приложения с предупреждениями или ограничениями при VPN

Для этих приложений источники описывают предупреждения или проблемы с доступом при VPN. По этим наблюдениям нельзя определить, как приложение распознаёт VPN и какие данные отправляет.

| Приложение | Пакет Android | Что зафиксировано |
| --- | --- | --- |
| билайн | `ru.beeline.services` | Приложение показывает предупреждение о VPN. [Проверка РБК](https://www.rbc.ru/technology_and_media/14/04/2026/69de94839a79471b62322d25) · [RuStore](https://www.rustore.ru/catalog/app/ru.beeline.services) |
| Ozon Банк | `ru.ozon.fintech.finance` | Отдельное банковское приложение предупреждает о VPN после входа. [Проверка РБК](https://www.rbc.ru/technology_and_media/14/04/2026/69de94839a79471b62322d25) · [RuStore](https://www.rustore.ru/catalog/app/ru.ozon.fintech.finance) |
| ВкусВилл | `ru.vkusvill` | Компания сообщила о возможных ограничениях в мобильном приложении при VPN. [Комментарий ВкусВилла](https://www.vedomosti.ru/technology/articles/2026/04/16/1190654-rossiiskie-servisi-nachali) · [RuStore](https://www.rustore.ru/catalog/app/ru.vkusvill) |
| Магнит | `ru.tander.magnit` | AdGuard сообщает об ограничениях в приложении при активном локальном VPN на Android. [AdGuard](https://adguard.com/ru/blog/android-apps-asking-to-disable-vpn.html) · [RuStore](https://www.rustore.ru/catalog/app/ru.tander.magnit) |
| Яндекс Пэй | `com.yandex.bank` | Опубликован экран ограничения доступа в приложении при VPN. [Проверка Т—Ж](https://t-j.ru/news/vpn-ban-apps/) · [RuStore](https://www.rustore.ru/catalog/app/com.yandex.bank) |
| Яндекс Лавка | `com.yandex.lavka` | Приложение предупреждает о возможных ошибках при VPN. [Проверка ТАСС](https://tass.ru/ekonomika/27112229) · [Google Play](https://play.google.com/store/apps/details?id=com.yandex.lavka) |
| Яндекс Погода | `ru.yandex.weatherplugin` | При запуске с VPN приложение показало экран ограничения доступа. [Проверка «Кода Дурова»](https://kod.ru/servisy-cherez-vpn-block) · [RuStore](https://www.rustore.ru/catalog/app/ru.yandex.weatherplugin) |
| Шоколадница | `ru.plazius.shokoladnica` | При запуске с VPN приложение показывает предупреждение. [Проверка РИА Новости](https://1prime.ru/20260409/vpn-869021094.html) · [Google Play](https://play.google.com/store/apps/details?id=ru.plazius.shokoladnica) |
| ИЛЬ ДЕ БОТЭ | `com.sephora.mobileapp` | Приложение предупреждает о возможных ошибках при VPN. [Проверка РИА Новости](https://1prime.ru/20260409/vpn-869021094.html) · [RuStore](https://www.rustore.ru/catalog/app/com.sephora.mobileapp) |
| Okko | `ru.more.play` | Приложение показало напоминание отключить VPN. [Проверка «Дождя»](https://t.me/tvrain/103445) · [RuStore](https://www.rustore.ru/catalog/app/ru.more.play) |
| АЗС «Газпромнефть» | `com.gpn.azs` | Пользователь Android сообщил об ограничении даже при раздельном туннелировании. Разработчик подтвердил требование отключить VPN. [Отзыв и ответ в RuStore](https://www.rustore.ru/catalog/app/com.gpn.azs?mt_link_id=rpn0r1&mt_sub1=prostore&mt_sub2=car-refueling-apps&mt_sub3=text&rsm=1) |

### Другие приложения из исследования LocalMess

Исследователи обнаружили в шести Android-приложениях Яндекса локальные порты, через которые скрипт Яндекс Метрики на сайте получал идентификаторы устройства. Карты, Браузер и Go уже есть в таблице RKS Global. По данным авторов, Яндекс прекратил использовать описанный механизм в июне 2025 года. [Исследование LocalMess](https://localmess.github.io/#yandex-using-localhost-communications-since-2017) · [Таблица пакетов](https://localmess.github.io/assets/bridges-to-self-localmess-usenix-security-26.pdf#page=20)

| Приложение | Пакет Android |
| --- | --- |
| Яндекс Навигатор | `ru.yandex.yandexnavi` |
| Яндекс с Алисой AI (Yandex Search в отчёте) | `com.yandex.searchapp` |
| Яндекс Метро | `ru.yandex.metro` |

## Happ

Подписка передаёт список обхода для Happ на Android при импорте и обновлении, в том числе с пустым Provider ID. Для автоматического применения Happ проверяет премиальный статус **Provider ID**, привязанного к адресу подписки. Если адрес подписки меняется, проверьте привязку нового адреса у Happ. [Настройки Happ](https://www.happ.su/main/ru/dev-docs/app-management#upravlenie-nastroikami-prilozheniya) · [Проверка Provider ID](https://docs.happ-proxy.com/ru/getting-started/how-to-start)

Чтобы выбрать приложения вручную, выполните два шага.

1. Откройте **Настройки → Прокси для выбранных приложений**.
2. Выберите **Обход**, отметьте установленные приложения из таблицы и переподключите VPN.

## INCY

На Android импортируйте или обновите подписку. Она передаст весь список и включит режим обхода. [Документация INCY](https://docs.incy.cc/app-management/)

Чтобы выбрать приложения вручную, выполните два шага.

1. В настройках откройте **Прокси по приложениям**.
2. Включите режим обхода, в котором выбранные приложения идут напрямую. Отметьте нужные приложения и переподключите VPN. [Трекер INCY](https://feedback.incy.cc/issues/cmqf8keg8000m118re0xvq1mb)

## v2RayTun

В Android-версии 5.26.83 подписка задаёт правила для доменов и IP, а стратегию разрешения доменов клиент берёт из своих настроек. При стратегии `AsIs` правило `geoip:ru` проверяет адреса, уже заданные как IP. Российские домены распознаются по отдельным правилам. Пользовательские правила клиента имеют приоритет над правилами подписки. [Сборка v2RayTun для Android](https://github.com/LXST-CODE/v2RayTun/releases/tag/android-v5.26.83)

1. Скопируйте содержимое [TXT-файла](../bundle/scripts/android-app-bypass.txt) в буфер обмена телефона.
2. Откройте **Настройки → Маршрутизация → Маршрутизация выбранных приложений**. Включите эту настройку и **Режим обхода**.
3. В меню **⋮** выберите **Импорт из буфера обмена**. В версии 5.26.83 импорт заменяет текущие отметки и выбирает приложения из списка, которые есть на устройстве. Если в вашей версии пункта нет, отметьте приложения вручную. Проверьте отметки и переподключите VPN. [v2RayTun для Android 5.26.83](https://github.com/LXST-CODE/v2RayTun/releases/tag/android-v5.26.83)

## Karing

1. Скопируйте содержимое [TXT-файла](../bundle/scripts/android-app-bypass.txt) в буфер обмена телефона.
2. Откройте **Настройки → TUN → Прокси по приложениям** (**Proxy by Application**). Включите этот фильтр и выключите **Режим белого списка** (**Whitelist Mode**), чтобы отмеченные приложения шли напрямую. Если Karing запрашивает доступ к списку приложений, разрешите его в настройках Android.
3. В меню **⋯** выберите **Импорт из буфера обмена** (**Import from Clipboard**). Если пункта нет в вашей версии, отметьте приложения вручную. Переподключите VPN. [Документация Karing](https://karing.app/ru/tutorial/perapp-proxy#режим-черного-списка) · [Импорт в исходном коде Karing](https://github.com/KaringX/karing/blob/v1.2.25.2802/lib/screens/perapp_android_screen.dart#L460-L499)

## Проверка на телефоне

С включённым VPN откройте один и тот же сайт проверки внешнего IP в исключённом и обычном браузере. Для проверки выберите сайт, который в обычном браузере маршрутизируется через VPN. В исключённом браузере должен быть IP обычного подключения, а во втором — IP выбранного VPN-выхода. Если исключённые приложения теряют сеть, проверьте параметр Android **Блокировать подключения без VPN**. [Документация Android](https://developer.android.com/develop/connectivity/vpn#blocked-connections)

Обход меняет маршрут трафика. Приложение всё ещё может обнаружить признаки активного VPN на устройстве. [Исследование RKS Global](https://rks.global/ru/research/vpn-detection/)
