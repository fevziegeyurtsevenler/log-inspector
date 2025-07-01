# Log Inspector: Gelişmiş Log Analizi ve Saldırı Tespit Aracı

Log Inspector, yüklenen log dosyalarını analiz ederek potansiyel güvenlik saldırılarını tespit etmek için tasarlanmış, kullanıcı dostu bir Streamlit uygulamasıdır. SQL Enjeksiyonu, Kaba Kuvvet (Brute Force), Dizin Dışına Çıkma (Directory Traversal), Komut Enjeksiyonu ve daha fazlası gibi çeşitli saldırı türlerini algılamak için özelleştirilebilir desenler kullanır.

## Özellikler

* **Esnek Log Formatı Desteği:** `config.yaml` dosyası üzerinden genel (generic) ve Nginx gibi farklı log formatlarını tanımlama yeteneği.
* **Kapsamlı Saldırı Tespiti:** Önceden tanımlanmış regex desenleri ile SQL Enjeksiyonu, XSS, Komut Enjeksiyonu, Web Shell ve daha birçok saldırı türünü algılar. Desenler kolayca genişletilebilir.
* **Özelleştirilebilir Kurallar:** Saldırı tespit kuralları, ciddiyet seviyeleri, açıklamalar ve öneriler `config.yaml` dosyası üzerinden yapılandırılabilir.
* **Etkileşimli Arayüz:** Streamlit tabanlı sezgisel web arayüzü sayesinde log dosyalarını kolayca yükleyebilir, analiz sonuçlarını görüntüleyebilir ve filtreleyebilirsiniz.
* **Görsel Analiz:** Tespit edilen saldırı türlerinin dağılımını ve en çok saldıran IP adreslerini grafiklerle görselleştirme.
* **Detaylı Raporlama:** Tespit edilen tüm saldırıların ayrıntılı bilgilerini içeren bir raporu TXT formatında indirme.
* **Beyaz Liste (Whitelist) Desteği:** Belirli IP adreslerini analizden hariç tutma imkanı.

## Kurulum

Projeyi yerel bilgisayarınızda çalıştırmak için aşağıdaki adımları izleyin:

### Ön Gereksinimler

* Python 3.7+
* `pip` (Python paket yöneticisi)

### Adımlar

1.  **Projeyi Klonlayın (veya İndirin):**
    ```bash
    git clone [https://github.com/fevziegeyurtsevenler/log-inspector.git](https://github.com/fevziegeyurtsevenler/log-inspector.git)
    cd log-inspector
    ```

2.  **Sanal Ortam Oluşturun (Önerilir):**
    ```bash
    python -m venv venv
    ```

3.  **Sanal Ortamı Etkinleştirin:**
    * **Windows:**
        ```bash
        .\venv\Scripts\activate
        ```
    * **macOS/Linux:**
        ```bash
        source venv/bin/activate
        ```

4.  **Gerekli Kütüphaneleri Yükleyin:**
    ```bash
    pip install -r requirements.txt
    ```

5.  **Uygulamayı Çalıştırın:**
    ```bash
    python3 -m streamlit run app.py
    ```

Tarayıcınızda otomatik olarak Log Inspector uygulaması açılacaktır.

## Kullanım

1.  Uygulama açıldığında, "Log dosyanızı yükleyin (.log, .txt)" butonuna tıklayarak analiz etmek istediğiniz log dosyasını seçin.
2.  Sol kenar çubuğundan log dosyanızın formatını (Generic veya Nginx) seçin.
3.  İsteğe bağlı olarak, belirli tarih aralıklarını, saldırı tiplerini veya IP adreslerini filtreleyebilir ya da beyaz listeye IP adresleri ekleyebilirsiniz.
4.  Uygulama, tespit edilen saldırıları özet panosu, grafikler ve detaylı bir tablo ile gösterecektir.
5.  "Detaylı Raporu İndir (.txt)" butonu ile tüm tespitlerin ayrıntılı bir raporunu alabilirsiniz.

## Saldırı Tespit Kurallarını Özelleştirme (`config.yaml`)

`config.yaml` dosyası, uygulamanın temel yapılandırma dosyasını oluşturur. Burada:

* `colors`: Grafikler için saldırı türlerine atanmış renkler.
* `log_formats`: Uygulamanın ayrıştırabileceği log formatlarının regex desenleri. Yeni log formatları buraya eklenebilir.
* `patterns`: Her saldırı türü için ayrı ayrı tanımlanmış tespit kuralları (regex), ciddiyet seviyesi (`severity`), kısa açıklama (`description`) ve öneri (`recommendation`) içerir. Mevcut kuralları değiştirebilir veya yeni saldırı türleri ve desenleri ekleyebilirsiniz.

**Örnek bir saldırı kuralı:**
```yaml
  SQL Injection:
    - regex: "union select"
      severity: "Yüksek"
      description: "Veritabanı tablolarını birleştirmeyi amaçlayan UNION SELECT enjeksiyonu."
      recommendation: "Giriş doğrulamayı ve parametreli sorguları kontrol edin."
