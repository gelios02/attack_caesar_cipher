# 🔐 Caesar Cipher Attack Tool

Простое веб-приложение на **Flask**, реализующее шифрование и расшифрование текста с помощью **шифра Цезаря**, а также атаки на шифр:

- 🔒 **Шифрование и расшифрование** текста с заданным ключом.
- 🎯 **Атака по известному открытому тексту** – определение ключа по паре "открытый текст – шифротекст".
- 🔍 **Атака по шифротексту (brute force)** – перебор всех ключей для расшифровки.
- 📖 **Словарная атака** – автоматическое определение осмысленного текста.

## 🚀 Установка и запуск

### 1️⃣ Клонирование репозитория
```sh
git clone https://github.com/your-username/attack_caesar_cipher.git
cd attack_caesar_cipher
2️⃣ Установка зависимостей
sh
Копировать
Редактировать
pip install -r requirements.txt
3️⃣ Запуск приложения
sh
Копировать
Редактировать
python app.py
После запуска приложение будет доступно по адресу: 👉 http://127.0.0.1:5000/

🎮 Использование
![Caesar Cipher Tool](static/images/ceaser.gif)

Зашифровать текст – вводите текст и ключ (0-25), получаете зашифрованный вариант.
Расшифровать текст – вводите шифротекст и ключ, получаете исходный текст.
Атака по открытому тексту – вводите пару "открытый текст – шифротекст", система вычисляет ключ.
Атака по шифротексту – вводите зашифрованный текст, получаете 26 вариантов расшифровки.
Словарная атака – вводите шифротекст, система выбирает наиболее осмысленный вариант.
📂 Структура проекта
csharp
Копировать
Редактировать
attack_caesar_cipher/
│── app.py                # Основной сервер Flask
│── requirements.txt       # Список зависимостей
│── static/
│   └── css/
│       └── style.css      # Стили приложения
│── templates/             # HTML-шаблоны
│   ├── base.html
│   ├── home.html
│   ├── encrypt.html
│   ├── decrypt.html
│   ├── attack_known.html
│   ├── attack_ciphertext.html
│   └── attack_dictionary.html
└── README.md              # Описание проекта
⚡ Технологии
Python 3
Flask
Bootstrap 5
HTML + CSS
