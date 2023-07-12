# PT Feeds Коннектор для PT Application Firewall PRO

Коннектор является внешним агентом, который забирает необходимые feed записи из приложения PT Feeds, фильтрует и передает информацию о компроментированных IP адресах в глобальные списки PT Application Firewall PRO.
Глобальные динамические списки используются в правилах фильтрации, блокировки или предупреждений для детектирования запросов к защищаемых Web приложениям от хостов, с которых была зафиксирована нелегитимная активность.

Репозиторий:
https://github.com/rootdm/ptaf-feed

Образ docker контейнера:
https://hub.docker.com/r/rootdm/ptaf-feed


PT Application Firewall:
https://www.ptsecurity.com/ru-ru/products/af/

------

## Запуск контейнера

- Перед запуском в хост-системе необходимо создать каталог conf, который подключается к контейнеру в `/app/conf`
- В каталоге размещается конфиг - `conf/ptaf-feed.ini` (см. пример ниже)

### Запуск коннектора в фоновом режиме через docker-compose
docker-compose.yml
```
version: '3.8'
services:
  ptaf-feed1:
    image: 'rootdm/ptaf-feed:latest'
    restart: unless-stopped
    container_name: ptaf-feed1
    volumes:
      - ./conf:/app/conf
```

```
docker-compose up -d
```

Среднее время работы одного цикла синхронизации - около 6 минут, что обусловлено текущем объемом фидов, получаемых от PT Feeds.

### Остановка коннектора
```
docker-compose down
```

### Проверка работы коннектора

Просмотр лог-файлов
```
docker logs -f ptaf-feed1
```

По результатам полного цикла импорта фидов создается файл conf/feeds_data.json, который содержит статистику по фидам и записи IP, которые экспортировались в PT AF.

------

## Настройка коннектора

Пример конфигурационного файла ptaf-feed.ini:
```
[GLOBAL]
; Debug Levels:
; 7 - Debug
; 6 - Info
; 4 - Warnings
; 3 - Errors
; 2 - Critical
; 0 - Disable logging
debug = 7

; Feed sync time (minutes)
sync_time = 720

[PTAF]
api_url = https://10.70.0.10/api/ptaf/v4
login = username
password = xxxxxxx
ip_ttl = 800
list_name = test_list
limit_per_request = 1000

[PTFEEDS]
api_url = https://10.70.0.23:2443/api
limit_per_request = 10000
```

#### Global - общие настройки коннектора
- debug - уровень детализации сообщений о работе: 7 - система логирует каждый шаг, 0 - отключение логирования;
- sync_time - периодичность (в минутах) синхронизации PT Feeds и PT AF;

#### PTAF - параметры экспорта фидов в PT AF
- api_url - полный URL адрес API интерфейса PT AF Pro
- login - имя пользователя с доступом к модификации глобальных списков
- password - пароль
- ip_ttl -  время жизни записи об IP адресе (в минутах)
- list_name - название пользовательского глобального списка, куда будут добавляться информация об IP адресах (должен быть преднастроен на PT AF)
- limit_per_request - количество переданных записей об IP адресах за один запрос

#### PTFEEDS - параметры импорта фидов из PT Feeds
- api_url - полный URL адрес API интерфейса агента PT Feeds
- limit_per_request - количество запрашиваемых записей за один запрос


------

## Вопросы и комментарии

Дмитрий Карякин
Email: dm@karyakin.ru
Telegram: https://t.me/dkaryakin

