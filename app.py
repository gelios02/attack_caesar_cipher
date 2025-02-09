from flask import Flask, request, render_template
import re

app = Flask(__name__)

# Небольшой словарь английских слов для демонстрации (можно расширить)
DICTIONARY = {
    "the", "be", "to", "of", "and", "a", "in", "that", "have", "i", "it", "for",
    "not", "on", "with", "he", "as", "you", "do", "at", "this", "but", "his", "by",
    "from", "they", "we", "say", "her", "she", "or", "an", "will", "my", "one", "all",
    "would", "there", "their", "what", "so", "up", "out", "if", "about", "who", "get",
    "which", "go", "me", "when", "make", "can", "like", "time", "no", "just", "him",
    "know", "take", "people", "into", "year", "your", "good", "some", "could", "them",
    "see", "other", "than", "then", "now", "look", "only", "come", "its", "over", "think",
    "also", "back", "after", "use", "two", "how", "our", "work", "first", "well", "way",
    "even", "new", "want", "because", "any", "these", "give", "day", "most", "us", "hello", "world"
}

# Функция шифрования: сдвиг каждого символа, если это буква латинского алфавита
def caesar_encrypt(text, key):
    result = ""
    for char in text:
        if char.isalpha():
            if char.isupper():
                base = ord('A')
            else:
                base = ord('a')
            # сдвиг по модулю 26
            result += chr((ord(char) - base + key) % 26 + base)
        else:
            result += char
    return result

# Расшифровка – то же, что шифрование с ключом (26 - key)
def caesar_decrypt(text, key):
    return caesar_encrypt(text, 26 - key)

# Атака по известному открытому тексту
def attack_known_plaintext(plain_text, cipher_text):
    for key in range(26):
        if caesar_encrypt(plain_text, key) == cipher_text:
            return key
    return None

# Атака «только по шифротексту»: возвращаем список вариантов расшифровки для всех ключей
def attack_ciphertext(cipher_text):
    possibilities = []
    for key in range(26):
        dec = caesar_decrypt(cipher_text, key)
        possibilities.append((key, dec))
    return possibilities

# Словарная атака: для каждого варианта подсчитываем количество «осмысленных» слов
def attack_dictionary(cipher_text):
    best_key = None
    best_text = None
    best_score = -1
    for key in range(26):
        dec = caesar_decrypt(cipher_text, key)
        # Извлекаем слова (только буквы)
        words = re.findall(r'\b[a-zA-Z]+\b', dec)
        # Подсчитываем, сколько слов встречаются в нашем словаре
        score = sum(1 for word in words if word.lower() in DICTIONARY)
        if score > best_score:
            best_score = score
            best_key = key
            best_text = dec
    return best_key, best_text, best_score

# Главная страница
@app.route("/")
def home():
    return render_template("home.html")

# Страница шифрования
@app.route("/encrypt", methods=["GET", "POST"])
def encrypt_route():
    result = None
    if request.method == "POST":
        text = request.form.get("text", "")
        try:
            key = int(request.form.get("key", "0"))
        except ValueError:
            key = 0
        result = caesar_encrypt(text, key)
    return render_template("encrypt.html", result=result)

# Страница расшифрования
@app.route("/decrypt", methods=["GET", "POST"])
def decrypt_route():
    result = None
    if request.method == "POST":
        text = request.form.get("text", "")
        try:
            key = int(request.form.get("key", "0"))
        except ValueError:
            key = 0
        result = caesar_decrypt(text, key)
    return render_template("decrypt.html", result=result)

# Атака по известному открытому тексту
@app.route("/attack_known", methods=["GET", "POST"])
def attack_known_route():
    key_found = None
    if request.method == "POST":
        plain_text = request.form.get("plain_text", "")
        cipher_text = request.form.get("cipher_text", "")
        key_found = attack_known_plaintext(plain_text, cipher_text)
    return render_template("attack_known.html", key_found=key_found)

# Атака по шифротексту (перебор всех вариантов)
@app.route("/attack_ciphertext", methods=["GET", "POST"])
def attack_ciphertext_route():
    possibilities = None
    if request.method == "POST":
        cipher_text = request.form.get("cipher_text", "")
        possibilities = attack_ciphertext(cipher_text)
    return render_template("attack_ciphertext.html", possibilities=possibilities)

# Словарная атака – выбор наиболее осмысленного варианта
@app.route("/attack_dictionary", methods=["GET", "POST"])
def attack_dictionary_route():
    result = None
    if request.method == "POST":
        cipher_text = request.form.get("cipher_text", "")
        key, text, score = attack_dictionary(cipher_text)
        result = (key, text, score)
    return render_template("attack_dictionary.html", result=result)

if __name__ == "__main__":
    app.run(debug=True)
