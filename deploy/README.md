# Боты на сервере 24/7 — пошагово

Схема: **один недорогой VPS, на нём все четыре бота** (запись и «Проверь ссылку», каждый в Telegram и MAX).
Боты работают в режиме polling: сами спрашивают у Telegram и MAX новые сообщения. Поэтому
не нужны ни домен, ни HTTPS-сертификат, ни открытые порты. Наружу открыт только SSH.

Время: около часа при первом разе.

---

## Какой сервер взять

| Параметр | Что нужно |
| --- | --- |
| Память | 1 ГБ (боты вместе занимают примерно 200–300 МБ, это моя оценка) |
| Процессор / диск | 1 ядро, 10–15 ГБ |
| Система | Ubuntu 24.04 |
| Расположение | **Нидерланды, Германия или Финляндия** |
| Оплата | картой «Мир» или по СБП |

**Почему не российский сервер.** Из России запросы к Telegram могут тормозить или блокироваться,
и бот будет отвечать с перебоями. Для демо и портфолио берём сервер за границей у провайдера,
который принимает рубли. Подобрать можно в каталоге
[hostinghub.ru](https://hostinghub.ru/top/vds/niderlandy-vps) (фильтры «Нидерланды» и «Карты Мир»).
Ориентир по цене — несколько сотен рублей в месяц. Это оценка: цены я не сверял.

**Важно для будущих клиентов.** Если бот собирает телефоны клиентов из России, по 152-ФЗ
их нужно хранить на сервере в России. Для заказчика это обычно российский VPS (и проверка, что
Telegram с него доступен). Наш демо-сервер хранит только тестовые записи, это нормально.

---

## Шаг 1. Ключ для входа (на Маке, один раз)

Вход по ключу безопаснее пароля: подобрать его невозможно.

```bash
ssh-keygen -t ed25519 -C "bots-server"
```

Трижды Enter (можно задать пароль к ключу, это ещё надёжнее). Потом выведи **публичную** часть:

```bash
cat ~/.ssh/id_ed25519.pub
```

Строку, которая начинается с `ssh-ed25519`, вставь при заказе сервера в поле «SSH-ключ».
Файл `id_ed25519` **без** `.pub` — секретный, его никому не отправляй.

## Шаг 2. Подключиться к серверу

IP-адрес сервера придёт в письме или будет в панели провайдера.

```bash
ssh root@IP_СЕРВЕРА
```

На вопрос `Are you sure you want to continue connecting` ответь `yes`.

## Шаг 3. Подготовить сервер (команды вводятся уже на сервере)

```bash
apt update && apt -y upgrade
apt -y install python3-venv git ufw unattended-upgrades tesseract-ocr tesseract-ocr-rus libzbar0
# Обновления безопасности будут ставиться сами
dpkg-reconfigure -f noninteractive unattended-upgrades
# Брандмауэр: снаружи открыт только SSH
ufw allow OpenSSH && ufw --force enable
# Запретить вход по паролю, оставить только по ключу
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart ssh
# Отдельный пользователь без прав администратора — боты работают от его имени
useradd --system --create-home --home-dir /opt/bots --shell /usr/sbin/nologin bots
```

## Шаг 4. Скачать код и поставить библиотеки

```bash
cd /opt/bots
git clone https://github.com/Klim-Mertens/booking-bot.git
git clone https://github.com/Klim-Mertens/proverka-ssylki.git
python3 -m venv booking-bot/.venv && booking-bot/.venv/bin/pip install -r booking-bot/requirements.txt
python3 -m venv proverka-ssylki/.venv && proverka-ssylki/.venv/bin/pip install -r proverka-ssylki/requirements.txt
cp booking-bot/config.example.toml booking-bot/config.toml
```

## Шаг 5. Секреты

Создай файлы `.env` и вставь в них те же строки, что у тебя на Маке:

```bash
nano /opt/bots/booking-bot/.env
nano /opt/bots/proverka-ssylki/.env
```

В nano: вставить — Cmd + V, сохранить — Ctrl + O и Enter, выйти — Ctrl + X.
Ключи `PII_ENC_KEY` и `PII_HMAC_KEY` возьми **те же**, что на Маке, если хочешь перенести базу.
Если база не нужна, сгенерируй новые.

Закрыть файлы от чужих глаз и отдать папки пользователю `bots`:

```bash
chown -R bots:bots /opt/bots
chmod 600 /opt/bots/*/.env
```

## Шаг 6. Запустить как службы

**Сначала останови ботов на Маке (Ctrl + C в каждом окне).** Один токен нельзя одновременно
опрашивать с двух компьютеров, Telegram вернёт ошибку `Conflict`.

```bash
cp /opt/bots/booking-bot/deploy/*.service /opt/bots/proverka-ssylki/deploy/*.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now booking-telegram booking-max proverka-telegram proverka-max
systemctl status booking-telegram --no-pager
```

Должно быть `active (running)`. Службы сами перезапускаются при сбое и после перезагрузки сервера.
Работают в «песочнице»: без прав root, без доступа к чужим папкам, с ограничением памяти.

## Полезные команды

| Задача | Команда |
| --- | --- |
| Посмотреть логи бота | `journalctl -u booking-telegram -n 50 --no-pager` |
| Перезапустить | `systemctl restart booking-telegram` |
| Обновить код с GitHub | `cd /opt/bots/booking-bot && sudo -u bots git pull && systemctl restart booking-telegram booking-max` |
| Остановить всё | `systemctl stop booking-telegram booking-max proverka-telegram proverka-max` |

Если служба не запускается, пришли мне вывод `journalctl` (сначала проверь, что в нём нет токенов).

## Мониторинг

У тебя есть UptimeRobot. Polling-боты не имеют веб-адреса, поэтому проверить их «по ссылке» нельзя.
Простой вариант — монитор типа **Ping** на IP сервера: узнаешь, если сервер упал целиком.
Упавшую службу systemd перезапустит сам.
