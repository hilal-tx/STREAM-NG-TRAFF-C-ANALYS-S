# traffic_analyzer.py

import pyshark
from scapy.all import * # Scapy'nin tüm fonksiyonlarını içeri aktarırız

# --- YAPILANDIRMA AYARLARI ---
# Ağ arayüzünüzün adını buraya girin.
# Hangi arayüzlerin kullanılabilir olduğunu görmek için 'pyshark.LiveCapture()' komutunu
# veya 'tshark -D' komutunu terminalde çalıştırabilirsiniz.
# Örn: 'Ethernet', 'Wi-Fi', 'en0', 'wlan0' gibi
NETWORK_INTERFACE = 'Wi-Fi' # Kendi arayüzünüze göre değiştirin!

# İzlemek istediğimiz uygulamaların yaygın sunucu IP adreslerini ve portlarını buraya ekleyebilirsiniz.
# Ancak HTTPS (443) kullanıldığında, bu IP'ler şifreli trafikte doğrudan görünmez.
# Yine de DNS sorguları veya SNI (Server Name Indication) alanları gibi yerlerden bilgi alınabilir.
# Bu örnekte genel HTTPS trafiğine odaklanacağız.
TARGET_PORTS = [443, 80] # HTTPS (443) ve HTTP (80)

# İzlenecek uygulama alan adlarının listesi (tam olarak şifreli trafik içinde filtrelemek zor olabilir)
# Bu sadece bilgilendirme amaçlıdır, doğrudan paket filtrelemede kullanılamaz.
APPLICATION_DOMAINS = {
    "YouTube": ["youtube.com", "googlevideo.com"],
    "Twitch": ["twitch.tv", "ttvnw.net"],
    "Spotify": ["spotify.com", "sp.analytics.spotify.com"]
}

# --- TRAFİK ANALİZİ FONKSİYONLARI ---

def analyze_packet_pyshark(packet):
    """
    Pyshark ile yakalanan her paketi analiz eder.
    """
    try:
        # Sadece IP katmanı olan paketleri işleyelim
        if 'IP' in packet:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst

            # Hedef portlarımızı kontrol edelim (TCP veya UDP)
            if 'TCP' in packet and int(packet.tcp.dstport) in TARGET_PORTS:
                dst_port = packet.tcp.dstport
                protocol = 'TCP'
                print(f"[PYSHARK] TCP Paket: {src_ip}:{packet.tcp.srcport} -> {dst_ip}:{dst_port} | Protokol: {protocol}")
                
                # Eğer HTTPS (443) ise, genellikle şifrelidir.
                if int(dst_port) == 443:
                    print("         (HTTPS trafiği, içeriği şifrelidir.)")
                
                # Daha detaylı bilgi almak isterseniz:
                # if 'http' in packet:
                #     print(f"  HTTP Yöntemi: {packet.http.request_method}")
                # if 'ssl' in packet and hasattr(packet.ssl, 'handshake_type'):
                #     print(f"  SSL/TLS Handshake Type: {packet.ssl.handshake_type}")


            elif 'UDP' in packet and int(packet.udp.dstport) in TARGET_PORTS:
                dst_port = packet.udp.dstport
                protocol = 'UDP'
                print(f"[PYSHARK] UDP Paket: {src_ip}:{packet.udp.srcport} -> {dst_ip}:{dst_port} | Protokol: {protocol}")
            
            # DNS sorgularını (UDP port 53) yakalayarak uygulama alan adı tahmini yapabiliriz
            elif 'DNS' in packet and 'UDP' in packet and int(packet.udp.dstport) == 53:
                if hasattr(packet.dns, 'qry_name'):
                    query_name = packet.dns.qry_name
                    print(f"[PYSHARK] DNS Sorgusu: {src_ip} -> {dst_ip}: {query_name}")
                    for app, domains in APPLICATION_DOMAINS.items():
                        for domain in domains:
                            if domain in query_name:
                                print(f"         Muhtemel Uygulama: {app}")

    except AttributeError:
        # Bazı paketlerde belirli katmanlar veya alanlar olmayabilir
        pass
    except Exception as e:
        print(f"Pyshark paket işleme hatası: {e}")

def analyze_packet_scapy(packet):
    """
    Scapy ile yakalanan her paketi analiz eder.
    Bu kısım, daha derinlemesine (low-level) analiz için bir örnektir.
    """
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            
            # Belirlenen portları hedefleyen TCP paketlerini yakala
            if dst_port in TARGET_PORTS:
                print(f"[SCAPY] TCP Paket: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                # if Raw in packet: # Paketin ham verisini görmek isterseniz
                #     print(f"  Raw Data: {packet[Raw].load}")

        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            
            # Belirlenen portları hedefleyen UDP paketlerini yakala
            if dst_port in TARGET_PORTS:
                print(f"[SCAPY] UDP Paket: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            
            # DNS sorgularını burada da kontrol edebiliriz
            if dst_port == 53 and DNS in packet:
                if packet[DNS].qr == 0: # Sorgu paketi ise
                    if packet[DNS].qd:
                        qname = packet[DNS].qd.qname.decode('utf-8').rstrip('.')
                        print(f"[SCAPY] DNS Sorgusu: {src_ip} -> {dst_ip}: {qname}")
                        for app, domains in APPLICATION_DOMAINS.items():
                            for domain in domains:
                                if domain in qname:
                                    print(f"         Muhtemel Uygulama: {app}")


def start_pyshark_capture():
    """
    Pyshark kullanarak ağ trafiğini yakalamaya başlar.
    """
    print(f"Pyshark ile '{NETWORK_INTERFACE}' arayüzünden trafik yakalanıyor... (Durdurmak için Ctrl+C)")
    try:
        # display_filter ile sadece belirli portları filtreleyebiliriz.
        # Bu, yakalanan paket sayısını azaltarak performansı artırır.
        capture_filter = f"tcp port {TARGET_PORTS[0]} or udp port {TARGET_PORTS[0]}"
        if len(TARGET_PORTS) > 1:
            for port in TARGET_PORTS[1:]:
                capture_filter += f" or tcp port {port} or udp port {port}"
        capture_filter += " or udp port 53" # DNS sorgularını da ekleyelim

        # Yakalama nesnesini oluştur
        capture = pyshark.LiveCapture(interface=NETWORK_INTERFACE, display_filter=capture_filter)
        
        # Her paket geldiğinde analyze_packet_pyshark fonksiyonunu çağır
        for packet in capture.sniff_continuously(packet_count=None): # Sonsuz yakalama
            analyze_packet_pyshark(packet)

    except Exception as e:
        print(f"Pyshark yakalama hatası: {e}")
        print("Arayüz adını kontrol ettiğinizden ve yönetici/root yetkileriyle çalıştığınızdan emin olun.")

def start_scapy_capture():
    """
    Scapy kullanarak ağ trafiğini yakalamaya başlar.
    Bu daha düşük seviyeli ve doğrudan paket işleme için uygundur.
    """
    print(f"Scapy ile '{NETWORK_INTERFACE}' arayüzünden trafik yakalanıyor... (Durdurmak için Ctrl+C)")
    try:
        # filter parametresi, Wireshark'taki gibi BPF (Berkeley Packet Filter) sözdizimini kullanır.
        scapy_filter = f"tcp port {TARGET_PORTS[0]} or udp port {TARGET_PORTS[0]}"
        if len(TARGET_PORTS) > 1:
            for port in TARGET_PORTS[1:]:
                scapy_filter += f" or tcp port {port} or udp port {port}"
        scapy_filter += " or udp port 53" # DNS sorgularını da ekleyelim

        sniff(iface=NETWORK_INTERFACE, prn=analyze_packet_scapy, filter=scapy_filter, store=0) # store=0 yakalanan paketleri bellekte tutmaz
    except Exception as e:
        print(f"Scapy yakalama hatası: {e}")
        print("Arayüz adını kontrol ettiğinizden ve yönetici/root yetkileriyle çalıştığınızdan emin olun.")

if _name_ == "_main_":
    print("Ağ Trafiği Analizi Başlatılıyor...")
    print("-----------------------------------")
    print("1. Pyshark ile Yakalama (Daha kolay ve Wireshark entegrasyonlu)")
    print("2. Scapy ile Yakalama (Daha düşük seviyeli kontrol)")
    print("-----------------------------------")
    choice = input("Lütfen bir seçenek girin (1 veya 2): ")

    if choice == '1':
        start_pyshark_capture()
    elif choice == '2':
        start_scapy_capture()
    else:
        print("Geçersiz seçim. Lütfen 1 veya 2 girin.")
