# STREAM-NG-TRAFF-C-ANALYS-S
Analysis and automated monitoring of network traffic for streaming platforms (Youtube,Spotify,Twitch)

# Network Traffic Analysis and Automated Monitoring of Streaming Platforms

---

*Team Members:*
* [Hilal Şengül] - [hilal-tx]


---

*Description:*
This project aims to deeply analyze the network traffic of popular streaming platforms such as YouTube, Twitch, and Spotify. Using the Wireshark tool, we investigate traffic structures, HTTPS connections, IP addresses, and port numbers. The collected data will be automatically monitored and analyzed using the Python programming language and relevant libraries (Scapy, Pyshark), allowing for a comparative evaluation of traffic densities across different platforms. Finally, the findings will be visualized with tables and graphs.

---

*Goals:*
* To thoroughly analyze the network traffic characteristics of YouTube, Twitch, and Spotify platforms using Wireshark.
* To identify IP addresses and port numbers used in HTTPS connections.
* To verify the ownership of detected IP addresses using whois queries.
* To develop real-time network traffic monitoring capabilities using Python (Scapy, Pyshark).
* To comparatively analyze traffic densities and packet structures across different platforms.
* To present meaningful results by visualizing the gathered data with tables and graphs.
* To professionally document project steps and findings on GitHub.

---
# 📡 Wireshark Uygulama Trafik Analizi

Bu dokümanda, Wireshark ile analiz edilen Spotify, Twitch ve YouTube uygulamalarının ağ trafiği yer almaktadır. Tüm trafik, güvenli bağlantı sağlayan *TLSv1.2 protokolü* üzerinden gerçekleşmiştir.

---

## 🎧 Spotify Trafik Özeti

- *Uygulama:* Spotify  
- *Protokol:* TLSv1.2  
- *Taşıma Protokolü:* TCP  
- *Kullanılan Port:* 443 (HTTPS)  
- *Açıklama:* Spotify uygulaması başlatıldığında, 443 numaralı port üzerinden TLSv1.2 ile şifreli bağlantı kurulmuştur. Veri aktarımı güvenli bir şekilde gerçekleşmiştir.

---

## 📺 Twitch Trafik Özeti

- *Uygulama:* Twitch  
- *Protokol:* TLSv1.2  
- *Taşıma Protokolü:* TCP  
- *Kullanılan Port:* 443 (HTTPS)  
- *Açıklama:* Twitch uygulaması açıldığında, TLS üzerinden 443 numaralı port kullanılarak şifreli bir bağlantı kurulmuştur.

---

## 📹 YouTube Trafik Özeti

- *Uygulama:* YouTube  
- *Protokol:* TLSv1.2  
- *Taşıma Protokolü:* TCP  
- *Kullanılan Port:* 443 (HTTPS)  
- *Paket Boyutu:* 124 bytes  
- *Açıklama:* YouTube uygulamasına ait bir bağlantı analiz edilmiştir. Trafik TLSv1.2 ile 443 portu üzerinden gerçekleşmiş ve 124 byte uzunluğunda bir paket gözlemlenmiştir.

---

## 🔒 Notlar

- Tüm bağlantılar şifrelenmiş olup TLSv1.2 protokolü ile gerçekleşmiştir.  
- IP adresleri güvenlik ve gizlilik amacıyla rapordan çıkarılmıştır.  
- 443 portu, HTTPS trafiği için kullanılan standart ve güvenli bağlantı noktasıdır.
---
*Links:
* [GitHub Repository Link] : https://github.com/hilal-tx/STREAM-NG-TRAFF-C-ANALYS-S/edit/main/README.md 
* Wireshark Official Website: https://www.wireshark.org/
* Scapy Library: https://scapy.net/
* Pyshark Library: https://kimin.github.io/pyshark/

