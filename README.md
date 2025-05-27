# Ağ Güvenliği Dersi Port Tarayıcı Projesi

Bu proje, Ağ Güvenliği dersi kapsamında geliştirilmiş bir port tarama uygulamasıdır. Uygulama, hedef sistemin açık portlarını tespit etmek ve işletim sistemi tahmini yapmak için kullanılır.

## Özellikler

- Hedef sistemin açık portlarını tespit etme
- İşletim sistemi tahmini
- Çoklu port tarama desteği (tek port, aralık veya virgülle ayrılmış portlar)
- Çoklu iş parçacığı (thread) desteği
- Detaylı tarama sonuçları

## Gereksinimler

- Python 3.x
- Yönetici (Administrator) yetkisi (raw socket kullanımı için)

## Kurulum

1. Projeyi bilgisayarınıza indirin
2. Gerekli Python paketlerini yükleyin:
   ```bash
   pip install -r requirements.txt
   ```

## Kullanım

Uygulamayı çalıştırmak için:

1. Komut istemini (Command Prompt) yönetici olarak açın
2. Proje dizinine gidin
3. Aşağıdaki komutlardan birini çalıştırın:
   ```bash
   sudo python3 app-console.py
   sudo python3 app.py
   ```

### Test için Port Açma

Uygulamayı test etmek için hedef sistemde port açabilirsiniz:

1. Netcat'i yükleyin:
   ```bash
   sudo apt install netcat-openbsd
   ```

2. Belirli bir portu dinlemeye alın (örnek: 8000 portu):
   ```bash
   nc -lvnp 8000
   ```

3. Açık portları listeleyin:
   ```bash
   ss -tuln
   ```

4. CTRL + C ile işlemi sonlandırın ve port dinlemeyi kapatın.

## Güvenlik Uyarısı

Bu uygulama sadece eğitim amaçlıdır ve yalnızca izin verilen sistemlerde kullanılmalıdır.

## Grup Üyeleri

* 402506 - İsmail Mert Öztürk
* 410448 - Mural Cemal Aygün
* 414922 - Mehmet Ali Orhan