from flask import Flask, request, render_template
import sqlite3

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/authorize', methods=['POST'])
def authorize():
    mac = request.form['mac']
    device_id = request.form['device_id']
    expected_network = request.form['expected_network']
    conn = sqlite3.connect('authorized_devices.db')
    c = conn.cursor()
    c.execute('''
        INSERT OR REPLACE INTO devices (mac, device_id, expected_network, authorized)
        VALUES (?, ?, ?, ?)
    ''', (mac, device_id, expected_network, 1))
    conn.commit()
    conn.close()
    return "授权成功"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)