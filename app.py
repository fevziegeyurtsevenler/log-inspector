import streamlit as st
import re
import yaml
import pandas as pd
import plotly.express as px
from collections import Counter
import datetime
import io

# --- Ayarları ve Kuralları Yükleme ---
@st.cache_data
def load_config(config_path='config.yaml'):
    with open(config_path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

config = load_config()
patterns_config = config['patterns'] # patterns adını patterns_config olarak değiştirdim çakışmaması için
colors = config['colors']
log_formats = config['log_formats']

# --- Log Ayrıştırma Fonksiyonu ---
def parse_log_line(line, log_format_regex):
    match = re.match(log_format_regex, line)
    if match:
        return match.groupdict()
    return {
        "zaman": "Bilinmiyor",
        "ip": "Bilinmiyor",
        "method": "Bilinmiyor",
        "url": "Bilinmiyor",
        "status": "Bilinmiyor"
    }

# --- Saldırı Tespit Fonksiyonu ---
def detect_attacks(log_lines, log_format_regex, patterns_config):
    results = []
    for i, line in enumerate(log_lines, 1):
        parsed = parse_log_line(line, log_format_regex)
        
        raw_line = line.strip()
        parsed_ip = parsed.get("ip", "Bilinmiyor")

        # Yeni patterns_config yapısına göre döngü
        for attack_type, rules_list in patterns_config.items():
            # rules_list artık doğrudan regex dizisi değil, her biri sözlük olan bir liste
            for rule in rules_list: 
                # Hata burada oluşuyorsa, 'rule' bir sözlük değil, bir string demektir.
                # config.yaml'nin doğru yüklendiğinden emin olun.
                regex = rule['regex'] # Kural sözlüğünden regex'i al
                
                if re.search(regex, raw_line, re.IGNORECASE):
                    results.append({
                        "satir_no": i,
                        "saldiri_tipi": attack_type,
                        "zaman": parsed.get("zaman", "Bilinmiyor"),
                        "ip": parsed_ip,
                        "method": parsed.get("method", "Bilinmiyor"),
                        "url": parsed.get("url", "Bilinmiyor"),
                        "severity": rule.get('severity', 'Bilinmiyor'), # Yeni alan
                        "description": rule.get('description', 'Açıklama yok.'), # Yeni alan
                        "recommendation": rule.get('recommendation', 'Öneri yok.'), # Yeni alan
                        "raw": raw_line
                    })
                    # Bir saldırı türü için bir kural eşleştiğinde, diğer kuralları kontrol etmeyi bırak
                    # Eğer aynı log satırında birden fazla farklı saldırı tipini yakalamak istiyorsanız,
                    # bu 'break' ifadesini kaldırabilirsiniz. Ancak şu anki mantık, bir kez eşleştiğinde yeterli sayıyor.
                    break 
    return results

# --- Ana Uygulama Fonksiyonu ---
def main():
    st.set_page_config(page_title="Log Inspector", layout="wide")
    st.title("Log Inspector - Gelişmiş Saldırı Tespit Aracı")

    uploaded_file = st.file_uploader("Log dosyanızı yükleyin (.log, .txt)", type=["log", "txt"])
    if not uploaded_file:
        st.info("Lütfen analiz için bir log dosyası yükleyin.")
        return

    try:
        content = uploaded_file.read().decode("utf-8").splitlines()
        st.write(f"Toplam {len(content)} satır yüklendi.")
    except Exception as e:
        st.error(f"Dosya okunurken bir hata oluştu: {e}")
        return

    # --- Filtreler (Sidebar) ---
    st.sidebar.header("Filtreler")

    selected_format_name = st.sidebar.selectbox(
        "Log Formatı Seçin",
        options=list(log_formats.keys())
    )
    log_format_regex = log_formats[selected_format_name]['regex']

    detections = detect_attacks(content, log_format_regex, patterns_config) # patterns_config'i fonksiyona geçir
    if not detections:
        st.success("Log dosyasında herhangi bir şüpheli aktivite bulunamadı.")
        return
    
    df = pd.DataFrame(detections)

    # --- Zaman sütununu datetime'a çevir ---
    def parse_log_time(time_str, format_name):
        try:
            if format_name == 'nginx':
                # Nginx formatı: [DD/Mon/YYYY:HH:MM:SS +0000]
                # Regex'ten gelen "zaman" stringi "[01/Jul/2025:10:30:00 +0000]" ise,
                # '01/Jul/2025:10:30:00 +0000' kısmını alıp parantezleri kaldırırız.
                if time_str.startswith('[') and time_str.endswith(']'):
                    time_str_cleaned = time_str[1:-1] # Köşeli parantezleri kaldır
                    return pd.to_datetime(time_str_cleaned, format='%d/%b/%Y:%H:%M:%S %z', errors='coerce')
                return pd.to_datetime(time_str, errors='coerce') # Varsayılan olarak dene
            elif format_name == 'generic':
                # Generic format: YYYY-MM-DD HH:MM:SS veya benzeri
                # pandas to_datetime genellikle yaygın formatları otomatik tanır
                return pd.to_datetime(time_str, errors='coerce')
            else:
                return pd.to_datetime(time_str, errors='coerce') # Tanımsız formatlar için genel deneme
        except Exception:
            return pd.NaT # Not a Time (Geçersiz zaman)

    # DataFrame'deki 'zaman' sütununu datetime objelerine dönüştür
    df['datetime'] = df['zaman'].apply(lambda x: parse_log_time(x, selected_format_name))
    
    # Geçersiz zaman değerlerini temizle veya kullanıcıya bildir
    initial_rows = len(df)
    df = df.dropna(subset=['datetime']) # Geçersiz zaman damgalarını içeren satırları kaldır
    if len(df) < initial_rows:
        st.warning(f"{initial_rows - len(df)} adet log satırındaki zaman damgaları ayrıştırılamadı ve filtrelenmeyecek.")

    # --- Tarih Aralığı Filtreleme ---
    # Eğer dataframe boş değilse ve geçerli datetime değerleri varsa min/max tarihleri al
    if not df.empty and pd.notna(df['datetime']).any():
        min_date_available = df['datetime'].min().date()
        max_date_available = df['datetime'].max().date()
    else:
        # Eğer loglarda hiç geçerli tarih yoksa veya df boşsa varsayılan değerler
        min_date_available = datetime.date.today() - datetime.timedelta(days=30)
        max_date_available = datetime.date.today()

    date_range_selection = st.sidebar.date_input(
        "Tarih Aralığı Seçin",
        value=(min_date_available, max_date_available),
        min_value=min_date_available,
        max_value=max_date_available
    )

    if len(date_range_selection) == 2:
        start_date = datetime.datetime.combine(date_range_selection[0], datetime.time.min)
        end_date = datetime.datetime.combine(date_range_selection[1], datetime.time.max)
        filtered_df = df[(df['datetime'] >= start_date) & (df['datetime'] <= end_date)].copy() # copy() ekledim
    else:
        filtered_df = df.copy() # Eğer tarih aralığı seçilmediyse tüm DataFrame'i kullan

    # Diğer Filtreler
    all_attack_types = sorted(filtered_df['saldiri_tipi'].unique())
    selected_attack_types = st.sidebar.multiselect("Saldırı Tipi Filtrele", options=all_attack_types, default=all_attack_types)
    
    all_ips = sorted(filtered_df['ip'].unique())
    selected_ips = st.sidebar.multiselect("IP Adresi Filtrele", options=all_ips)

    # Filtreleri uygula
    if selected_attack_types:
        filtered_df = filtered_df[filtered_df['saldiri_tipi'].isin(selected_attack_types)]
    if selected_ips:
        filtered_df = filtered_df[filtered_df['ip'].isin(selected_ips)]

    # --- Sonuçların Gösterimi ---
    st.header("Tespit Edilen Potansiyel Saldırılar")

    if filtered_df.empty:
        st.success("Seçimlerinize uygun şüpheli aktivite bulunamadı.")
        return

    st.warning(f"Filtrelenmiş {len(filtered_df)} potansiyel saldırı tespit edildi!")

    # Dashboard Metrikleri
    st.subheader("Özet Pano")
    col1, col2, col3 = st.columns(3)
    col1.metric("Toplam Tespit", len(filtered_df))
    
    if not filtered_df.empty:
        top_attacker_series = filtered_df['ip'].value_counts()
        if not top_attacker_series.empty:
            top_attacker = top_attacker_series.idxmax()
            top_attack_count = top_attacker_series.max()
            col2.metric("En Çok Saldıran IP", f"{top_attacker} ({top_attack_count} kez)")
        else:
            col2.metric("En Çok Saldıran IP", "Yok")

        top_attack_type_series = filtered_df['saldiri_tipi'].value_counts()
        if not top_attack_type_series.empty:
            top_attack_type = top_attack_type_series.idxmax()
            col3.metric("En Sık Görülen Saldırı", top_attack_type)
        else:
            col3.metric("En Sık Görülen Saldırı", "Yok")
    else:
        col2.metric("En Çok Saldıran IP", "Yok")
        col3.metric("En Sık Görülen Saldırı", "Yok")


    # Veri Görselleştirme
    st.subheader("Analiz Grafikleri")
    c1, c2 = st.columns(2)
    
    with c1:
        attack_counts = filtered_df['saldiri_tipi'].value_counts()
        if not attack_counts.empty:
            fig_pie = px.pie(
                values=attack_counts.values, 
                names=attack_counts.index, 
                title="Saldırı Türlerine Göre Dağılım",
                color_discrete_map=colors
            )
            st.plotly_chart(fig_pie, use_container_width=True)
        else:
            st.info("Saldırı türlerine göre dağılım grafiği için yeterli veri yok.")


    with c2:
        top_ips = filtered_df['ip'].value_counts().nlargest(10)
        if not top_ips.empty:
            fig_bar = px.bar(
                x=top_ips.index, 
                y=top_ips.values, 
                title="Top 10 Saldırgan IP Adresi",
                labels={'x': 'IP Adresi', 'y': 'Saldırı Sayısı'}
            )
            st.plotly_chart(fig_bar, use_container_width=True)
        else:
            st.info("Top 10 Saldırgan IP Adresi grafiği için yeterli veri yok.")


    # Etkileşimli Tablo (Yeni alanlar eklendi)
    st.subheader("Saldırı Detayları")
    # 'description' ve 'recommendation' sütunlarının varlığını kontrol edelim
    display_columns = ['satir_no', 'zaman', 'ip', 'saldiri_tipi', 'severity', 'method', 'raw']
    if 'description' in filtered_df.columns:
        display_columns.insert(display_columns.index('raw'), 'description')
    if 'recommendation' in filtered_df.columns:
        display_columns.insert(display_columns.index('raw') + 1 if 'description' in display_columns else display_columns.index('raw'), 'recommendation')

    st.dataframe(filtered_df[display_columns], use_container_width=True)

    # Rapor indirme butonu (Yeni alanlar eklendi)
    if st.button("Detaylı Raporu İndir (.txt)"):
        report = io.StringIO()
        report.write(f"Log Inspector Raporu - {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        report.write(f"Toplam Satır: {len(content)}\n")
        report.write(f"Tespit Edilen Saldırı Sayısı: {len(filtered_df)}\n\n")
        
        # Sadece görünür sütunları rapora dahil et
        for index, row in filtered_df.iterrows():
            report.write("-" * 50 + "\n")
            report.write(f"Satır {row['satir_no']} - {row['saldiri_tipi']}\n")
            report.write(f"  Zaman: {row['zaman']}\n")
            report.write(f"  IP: {row['ip']}\n")
            report.write(f"  Method: {row['method']}\n")
            report.write(f"  URL: {row['url']}\n")
            report.write(f"  Ciddiyet: {row.get('severity', 'Bilinmiyor')}\n")
            report.write(f"  Açıklama: {row.get('description', 'Açıklama yok.')}\n")
            report.write(f"  Öneri: {row.get('recommendation', 'Öneri yok.')}\n")
            report.write(f"  Satır İçeriği: {row['raw']}\n\n")
        
        st.download_button(
            label="Raporu Kaydet",
            data=report.getvalue(),
            file_name="log_inspector_report.txt",
            mime="text/plain"
        )

    st.markdown("---")
    st.markdown(
        "### Proje Sahibi: Fevzi Ege Yurtsevenler\n"
        "[LinkedIn Profili](https://www.linkedin.com/in/fevziege/)"
    )

if __name__ == "__main__":
    main()