import argparse
import sqlite3
import time
from collections import defaultdict, deque
from scapy.all import sniff, IP, TCP, UDP
import matplotlib.pyplot as plt
import matplotlib.animation as animation
from threading import Thread
import smtplib
from email.mime.text import MIMEText

# Database setup
DB_NAME = 'traffic.db'

def create_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS packets (
                    id INTEGER PRIMARY KEY,
                    timestamp REAL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT,
                    length INTEGER,
                    flags TEXT
                )''')
    conn.commit()
    conn.close()

def log_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        length = len(packet)
        protocol = packet[IP].proto
        flags = ''
        src_port = dst_port = None
        
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = str(packet[TCP].flags)
            protocol = 'TCP'
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            protocol = 'UDP'
        
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute('INSERT INTO packets (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length, flags) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                  (time.time(), src_ip, dst_ip, src_port, dst_port, protocol, length, flags))
        conn.commit()
        conn.close()

# Anomaly detection
class AnomalyDetector:
    def __init__(self):
        self.syn_counts = defaultdict(int)  # For port scanning
        self.packet_counts = deque(maxlen=10)  # For flooding (packets per second)
        self.last_time = time.time()
        self.alert_threshold_syn = 10  # SYN packets to different ports
        self.alert_threshold_flood = 100  # Packets per second
    
    def check_packet(self, packet):
        current_time = time.time()
        
        # Flooding detection
        if current_time - self.last_time >= 1:
            self.packet_counts.append(len(self.packet_counts) + 1 if self.packet_counts else 1)
            self.last_time = current_time
            if len(self.packet_counts) >= 10 and sum(self.packet_counts) / len(self.packet_counts) > self.alert_threshold_flood:
                alert("Flooding detected!")
        
        # Port scanning detection (SYN packets)
        if TCP in packet and packet[TCP].flags == 'S':  # SYN flag
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport
            key = (src_ip, dst_port)
            self.syn_counts[key] += 1
            if self.syn_counts[key] > self.alert_threshold_syn:
                alert(f"Port scanning detected from {src_ip} to port {dst_port}")

def alert(message):
    print(f"ALERT: {message}")
    # Optional: Send email
    # send_email(message)

def send_email(message):
    # Configure your email settings
    sender = 'your_email@example.com'
    receiver = 'alert@example.com'
    msg = MIMEText(message)
    msg['Subject'] = 'Network Anomaly Alert'
    msg['From'] = sender
    msg['To'] = receiver
    
    try:
        server = smtplib.SMTP('smtp.example.com', 587)
        server.starttls()
        server.login(sender, 'password')
        server.sendmail(sender, receiver, msg.as_string())
        server.quit()
    except Exception as e:
        print(f"Email send failed: {e}")

# Live plotting
def live_plot():
    fig, ax = plt.subplots()
    xdata, ydata = [], []
    
    def update(frame):
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute('SELECT COUNT(*) FROM packets WHERE timestamp > ?', (time.time() - 60,))
        count = c.fetchone()[0]
        conn.close()
        
        xdata.append(time.time())
        ydata.append(count)
        if len(xdata) > 100:
            xdata.pop(0)
            ydata.pop(0)
        
        ax.clear()
        ax.plot(xdata, ydata)
        ax.set_xlabel('Time')
        ax.set_ylabel('Packets per minute')
        ax.set_title('Live Traffic')
    
    ani = animation.FuncAnimation(fig, update, interval=1000)
    plt.show()

def main():
    parser = argparse.ArgumentParser(description="Network Packet Sniffer with Anomaly Detection")
    parser.add_argument('--interface', default='eth0', help='Network interface to sniff (default: eth0)')
    parser.add_argument('--gui', action='store_true', help='Enable live GUI plot')
    args = parser.parse_args()
    
    create_db()
    detector = AnomalyDetector()
    
    if args.gui:
        plot_thread = Thread(target=live_plot)
        plot_thread.start()
    
    def packet_callback(packet):
        log_packet(packet)
        detector.check_packet(packet)
    
    print("Starting packet sniffer... Press Ctrl+C to stop.")
    try:
        sniff(iface=args.interface, prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("Sniffer stopped.")
        # Display summary
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute('SELECT COUNT(*), protocol FROM packets GROUP BY protocol')
        summary = c.fetchall()
        conn.close()
        print("Traffic Summary:")
        for count, proto in summary:
            print(f"{proto}: {count} packets")

if __name__ == "__main__":
    main()