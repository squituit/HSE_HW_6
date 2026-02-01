#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Импортируем всё необходимое из Scapy для анализа сетевых пакетов
from scapy.all import *

# Модуль для разбора URL (например, извлечение параметров из ?q=...)
import urllib.parse

# Модуль для поиска сложных шаблонов с помощью регулярных выражений
import re

# IP-адрес сервера Google Gruyere (взят через nslookup)
GRUYERE_HOST = "216.58.210.180"
# Порт HTTP
GRUYERE_PORT = 80

# Открываем файл для записи всех событий (режим добавления, UTF-8 для поддержки спецсимволов)
log_file = open("result.log", "a", encoding="utf-8")

# Список регулярных выражений — сигнатуры XSS-атак, которые мы ищем
XSS_PATTERNS = [
    r'<script.*?>',           # любой открывающий тег <script ...>
    r'javascript:',           # ссылки вида javascript:alert(1)
    r'on\w+\s*=',             # обработчики событий: onclick=, onerror=, onload= и т.д.
    r'<svg.*?onload',         # вектор через SVG-изображение
    r'<img.*?onerror',        # классический вектор через изображение
    r'alert\(',               # вызов alert() — часто используется в PoC
    r'document\.cookie'       # попытка доступа к кукам — признак эксплуатации
]

# Проверяем, содержит ли строка признаки XSS
def is_xss_payload(data: str) -> bool:
    # Приводим к нижнему регистру для регистронезависимого поиска
    data_lower = data.lower()
    # Перебираем все шаблоны XSS
    for pattern in XSS_PATTERNS:
        # Ищем совпадение с учётом:
        #   re.IGNORECASE — игнорировать регистр (на всякий случай),
        #   re.DOTALL — символ '.' совпадает и с переносом строки
        if re.search(pattern, data_lower, re.IGNORECASE | re.DOTALL):
            return True  # Найдено — уязвимость возможна
    return False  # Ничего не найдено

#Извлекаем HTTP-данные из сетевого пакета
def extract_http_data(packet):
    # Проверяем наличие обязательных сетевых слоёв: IP, TCP, данные (Raw)
    if not (packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw)):
        return None  # Не HTTP — выходим

    # Извлекаем IP-адреса отправителя и получателя
    ip_src = packet[IP].src
    ip_dst = packet[IP].dst

    # Извлекаем TCP-порты
    sport = packet[TCP].sport
    dport = packet[TCP].dport

    # Получаем сырые байты полезной нагрузки
    raw_data = packet[Raw].load

    # Пытаемся декодировать байты в текст (UTF-8), игнорируя ошибки
    try:
        http_str = raw_data.decode('utf-8', errors='ignore')
    except:
        return None  # Не удалось — не HTTP

    # Определяем тип сообщения:
    # Запрос начинается с HTTP-глагола (GET, POST и т.д.)
    is_request = any(http_str.startswith(method) for method in ["GET ", "POST ", "PUT ", "HEAD "])
    # Ответ начинается с "HTTP/"
    is_response = http_str.startswith("HTTP/")

    # Возвращаем структурированные данные
    return {
        'src': ip_src,
        'dst': ip_dst,
        'sport': sport,
        'dport': dport,
        'data': http_str,
        'is_request': is_request,
        'is_response': is_response
    }

# Анализируем каждый пакет на предмет XSS
def analyze_packet(packet):
    # Извлекаем HTTP-данные
    http = extract_http_data(packet)
    if not http:
        return  # Не HTTP — пропускаем

    # Сохраняем для удобства
    src, dst = http['src'], http['dst']
    data = http['data']

    # Фильтруем ТОЛЬКО трафик, связанный с Gruyere либо пакет ОТ сервера, либо К серверу
    if not (
        (src == GRUYERE_HOST and http['sport'] == GRUYERE_PORT) or
        (dst == GRUYERE_HOST and http['dport'] == GRUYERE_PORT)
    ):
        return  # Не наш трафик — игнорируем

    # Вспомогательная функция: выводит сообщение и записывает в файл
    def log_msg(msg):
        print(msg)  # В консоль
        log_file.write(msg + "\n")  # В файл
        log_file.flush()  # Сразу сохраняем на диск

    # Если это HTTP-запрос (от клиента к серверу)
    if http['is_request']:
        # Проверяем весь запрос на XSS (включая строку запроса и заголовки)
        if is_xss_payload(data):
            log_msg(f"\nXSS-запрос от {src} → {dst}")
            log_msg("-" * 60)
            log_msg(data[:1000])  # Первые 1000 символов

        # Обработка GET-запросов: извлекаем параметры из URL
        if data.startswith("GET "):
            try:
                # Первая строка: "GET /path?param=value HTTP/1.1"
                path_line = data.split("\r\n")[0]
                # Извлекаем путь с параметрами: "/path?param=value"
                url_part = path_line.split(" ")[1]
                # Если есть параметры (после "?")
                if "?" in url_part:
                    # Берём часть после "?"
                    query_string = url_part.split("?", 1)[1]
                    # Парсим в словарь: {'param': ['value']}
                    params = urllib.parse.parse_qs(query_string)
                    # Проверяем каждое значение параметра
                    for key, values in params.items():
                        for val in values:
                            if is_xss_payload(val):
                                log_msg(f"\nXSS в параметре GET '{key}': {val}")
            except Exception:
                pass  # Ошибки парсинга игнорируем

        # Обработка POST-запросов: анализируем тело
        if data.startswith("POST "):
            # Находим начало тела (после \r\n\r\n)
            body_start = data.find("\r\n\r\n")
            if body_start != -1:
                body = data[body_start + 4:]  # Пропускаем 4 символа \r\n\r\n
                if is_xss_payload(body):
                    log_msg(f"\n[!]XSS в теле POST-запроса!")
                    log_msg(body[:500])  # Первые 500 символов тела

    # Если это HTTP-ответ (от сервера к клиенту)
    elif http['is_response']:
        # Проверяем весь ответ на отражённый XSS
        if is_xss_payload(data):
            log_msg(f"\n[+] XSS в ответе от {src}!")
            log_msg("-" * 60)
            # Извлекаем тело ответа (после заголовков)
            body_start = data.find("\r\n\r\n")
            if body_start != -1:
                # Берём фрагмент тела (до 800 символов)
                body = data[body_start + 4: body_start + 800]
                log_msg(body)


if __name__ == "__main__":

    print(f"[+] Запуск XSS-сниффера для Gruyere ({GRUYERE_HOST}:{GRUYERE_PORT})")
    print("[*] Логи записываются в result.log")
    print("[*] Пример XSS: <img src=x onerror=alert(document.cookie)>")

    try:
        sniff(
            filter=f"tcp port {GRUYERE_PORT}",
            prn=analyze_packet,
            store=0
        )
    except KeyboardInterrupt:
        print("\n[!] Остановлено пользователем.")
        log_file.close() 