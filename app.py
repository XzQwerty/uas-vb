import paho.mqtt.client as mqtt
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import json
from flask import Flask, render_template
from flask_socketio import SocketIO

# Konfigurasi MQTT
MQTT_BROKER = "broker.emqx.io"
MQTT_PORT = 1883
MQTT_TOPIC = "tugas/vb"
MQTT_USER = "akmal"
MQTT_PASSWORD = "12345"

# Kunci AES dan IV (sesuaikan persis dengan ESP32)
AES_KEY = b'\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x61\x62\x63\x64\x65\x66'
AES_IV = b'\x61\x62\x63\x64\x65\x66\x39\x38\x37\x36\x35\x34\x33\x32\x31\x30'

# Setup Flask dan SocketIO
app = Flask(__name__)
socketio = SocketIO(app)

# Variabel global untuk menyimpan data terakhir
last_25_data = []

# Fungsi untuk dekripsi AES
def decrypt_aes(encrypted_data: str) -> str:
    try:
        cipher_bytes = base64.b64decode(encrypted_data)
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        decrypted_padded = cipher.decrypt(cipher_bytes)
        decrypted = unpad(decrypted_padded, AES.block_size)
        return decrypted.decode('utf-8')
    except Exception as e:
        print(f"Dekripsi gagal: {e}")
        return None

# Callback saat berhasil terhubung ke broker MQTT
def on_connect(client, userdata, flags, rc, properties=None):
    print("Terhubung ke broker MQTT")
    client.subscribe(MQTT_TOPIC)

# Callback saat menerima pesan MQTT
def on_message(client, userdata, msg):
    try:
        payload = msg.payload.decode('utf-8')
        payload_json = json.loads(payload)

        encrypted_data = payload_json.get('encrypted_data', '')
        received_hash = payload_json.get('hash', '')

        decrypted_data = decrypt_aes(encrypted_data)

        if decrypted_data:
            # Ekstrak timestamp dan distance
            timestamp, distance = decrypted_data.split(', ')
            timestamp = timestamp.split(': ')[1]  # Ambil nilai timestamp
            distance = distance.split(': ')[1]    # Ambil nilai distance (dengan satuan)

            # Hapus satuan 'cm' dari distance
            distance = distance.replace('cm', '').strip()  # Hapus 'cm' dan spasi

            try:
                # Konversi distance menjadi float
                distance = float(distance)
            except ValueError:
                print(f"Kesalahan konversi distance: {distance}")
                return  # Abaikan pesan jika jarak tidak valid

            calculated_hash = hashlib.sha256(decrypted_data.encode('utf-8')).hexdigest()
            valid_hash = calculated_hash == received_hash

            new_data = {
                "timestamp": timestamp,
                "distance": distance,
                "encrypted_data": encrypted_data,
                "received_hash": received_hash,
                "calculated_hash": calculated_hash,
                "valid_hash": valid_hash
            }

            # Simpan data ke buffer
            last_25_data.append(new_data)
            if len(last_25_data) > 25:
                last_25_data.pop(0)

            # Emit data ke frontend melalui Socket.IO
            socketio.emit('update_data', {"last_25_data": last_25_data})
            print(f"Data dikirim ke frontend: {new_data}")

    except Exception as e:
        print(f"Kesalahan memproses pesan: {e}")

# Setup MQTT Client
client = mqtt.Client()
client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
client.on_connect = on_connect
client.on_message = on_message

# Route utama untuk render HTML
@app.route('/')
def index():
    return render_template('index.html')

# Jalankan Flask dan MQTT Client
if __name__ == "__main__":
    client.loop_start()
    client.connect(MQTT_BROKER, MQTT_PORT, 60)
    socketio.run(app, host='0.0.0.0', port=5000)
