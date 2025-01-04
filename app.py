from flask import Flask, render_template, request, jsonify, flash
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
import os


load_dotenv()

app = Flask(__name__, static_folder='static', template_folder='templates')


app.secret_key = os.getenv('SECRET_KEY')  # Ambil SECRET_KEY dari file .env

def encrypt_seed_phrase(seed_phrase, secret_key):
    cipher = AES.new(secret_key.encode(), AES.MODE_ECB)
    padded_seed_phrase = pad(seed_phrase.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded_seed_phrase)
    encrypted_seed_phrase = base64.b64encode(ciphertext).decode('utf-8')
    return encrypted_seed_phrase

def decrypt_seed_phrase(encrypted_seed_phrase, secret_key_bytes):
    encrypted_seed_phrase_bytes = base64.b64decode(encrypted_seed_phrase)
    cipher = AES.new(secret_key_bytes, AES.MODE_ECB)
    decrypted_seed_phrase = cipher.decrypt(encrypted_seed_phrase_bytes)
    decrypted_seed_phrase = unpad(decrypted_seed_phrase, AES.block_size)
    return decrypted_seed_phrase.decode()

def caesar_cipher_encrypt(text, shift):
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            shifted = ord(char) + shift
            if char.islower():
                if shifted > ord('z'):
                    shifted -= 26
            elif char.isupper():
                if shifted > ord('Z'):
                    shifted -= 26
            encrypted_text += chr(shifted)
        else:
            encrypted_text += char
    return encrypted_text

def caesar_cipher_decrypt(text, shift):
    return caesar_cipher_encrypt(text, -shift)

def send_encrypted_email(ciphertext_seed_phrase, encrypted_secret_key, email_1, email_2):
    smtp_server = "smtp.gmail.com"
    port = 587
    sender_email = os.getenv('SENDER_EMAIL')  
    password = os.getenv('EMAIL_PASSWORD')  

    # membuat email seedphrasee
    msg_seed_phrase = MIMEMultipart()
    msg_seed_phrase['From'] = sender_email
    msg_seed_phrase['To'] = email_1
    msg_seed_phrase['Subject'] = "Encrypted Seed Phrase Result"
    body_seed_phrase = f"Ciphertext Seed Phrase: {ciphertext_seed_phrase}"
    msg_seed_phrase.attach(MIMEText(body_seed_phrase, 'plain'))

    # mengirim email
    with smtplib.SMTP(smtp_server, port) as server:
        server.starttls()
        server.login(sender_email, password)
        server.send_message(msg_seed_phrase)

    # membuat email secret key
    msg_secret_key = MIMEMultipart()
    msg_secret_key['From'] = sender_email
    msg_secret_key['To'] = email_2
    msg_secret_key['Subject'] = "Encrypted Secret Key Result"
    body_secret_key = f"Encrypted Secret Key: {encrypted_secret_key}"
    msg_secret_key.attach(MIMEText(body_secret_key, 'plain'))

    # mengirim email
    with smtplib.SMTP(smtp_server, port) as server:
        server.starttls()
        server.login(sender_email, password)
        server.send_message(msg_secret_key)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json
    seed_phrase = data['seed_phrase']
    secret_key = data['secret_key']
    email_1 = data['email_1']
    email_2 = data['email_2']

    encrypted_seed_phrase = encrypt_seed_phrase(seed_phrase, secret_key)
    secret_key_shift = 3
    encrypted_secret_key = caesar_cipher_encrypt(secret_key, secret_key_shift)

    send_encrypted_email(encrypted_seed_phrase, encrypted_secret_key, email_1, email_2)
    
    flash('Pesan enkripsi berhasil dikirim!', 'success') 
    return jsonify({'message': 'Pesan enkripsi berhasil dikirim.'})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.json
    encrypted_seed_phrase = data['encrypted_seed_phrase']
    encrypted_secret_key = data['encrypted_secret_key']

    secret_key_shift = 3
    decrypted_secret_key = caesar_cipher_decrypt(encrypted_secret_key, secret_key_shift)
    decrypted_seed_phrase = decrypt_seed_phrase(encrypted_seed_phrase, decrypted_secret_key.encode())

    return jsonify({'decrypted_seed_phrase': decrypted_seed_phrase})

if __name__ == "__main__":
    app.run(debug=True)
