#!/usr/bin/env python3

# Aydınlatan ve geliştiren bilimin adıyla:

import sys
import os
import subprocess
import time
import json 
import re 
import hashlib
from configparser import ConfigParser 

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QStackedWidget, QRadioButton, QSizePolicy, 
    QGridLayout, QComboBox, QGroupBox, QMessageBox, QProgressBar, QTextEdit,
    QFileDialog, QLineEdit 
)
from PyQt5.QtCore import Qt, QSize, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QPixmap, QIcon 

# GNOME ortamında düzgün sorunsuz başlaması için:

os.environ['QT_QPA_PLATFORM'] = 'xcb'

# --- Dil Desteği ---
class LanguageManager:
    def __init__(self):
        self.current_language = 'English'  # Varsayılan dil İngilizce
        self.translations = {}
        self.config_dir = os.path.expanduser('~/.config/SysBackRes')
        self.config_file = os.path.join(self.config_dir, 'userdata.json')
        self.available_languages = self.get_available_languages()
        self.load_user_config()
        self.load_language(self.current_language)
        

    
    def get_available_languages(self):
        """languages klasöründeki mevcut dilleri tespit eder"""
        languages = []
        lang_dir = os.path.join(os.path.dirname(__file__), 'languages')
        if os.path.exists(lang_dir):
            for file in os.listdir(lang_dir):
                if file.endswith('.ini'):
                    lang_name = file[:-4]  # .ini uzantısını kaldır
                    languages.append(lang_name)
        return sorted(languages) if languages else ['English']
    
    def load_user_config(self):
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    self.current_language = config.get('language', 'English')
        except:
            pass
    
    def save_user_config(self):
        try:
            os.makedirs(self.config_dir, exist_ok=True)
            config = {'language': self.current_language}
            with open(self.config_file, 'w') as f:
                json.dump(config, f)
        except:
            pass
    
    def load_language(self, lang_name):
        try:
            lang_file = os.path.join(os.path.dirname(__file__), 'languages', f'{lang_name}.ini')
            config = ConfigParser()
            config.read(lang_file, encoding='utf-8')
            self.translations = dict(config['STRINGS']) if 'STRINGS' in config else {}
            self.current_language = lang_name
        except:
            # Fallback to English
            try:
                lang_file = os.path.join(os.path.dirname(__file__), 'languages', 'English.ini')
                config = ConfigParser()
                config.read(lang_file, encoding='utf-8')
                self.translations = dict(config['STRINGS']) if 'STRINGS' in config else {}
                self.current_language = 'English'
            except:
                self.translations = {}
    
    def get(self, key, *args):
        if key == 'wizard_titles':
            # wizard_titles için özel işlem
            titles = []
            for i in range(7):
                title_key = f'wizard_title_{i}'
                titles.append(self.translations.get(title_key, title_key))
            return titles
        
        text = self.translations.get(key, key)
        # \n escape karakterlerini gerçek satır sonlarına çevir
        text = text.replace('\\n', '\n')
        if args:
            try:
                return text.format(*args)
            except:
                return text
        return text
    
    def set_language(self, lang_name):
        self.load_language(lang_name)
        self.save_user_config()

# Global language manager
lang = LanguageManager()

# --- Sabitler ve Kaynak Yolu Yardımcı Fonksiyonu ---

# Resim ve Pencere Boyutları
IMAGE_WIDTH = 150 
WINDOW_WIDTH = 700
WINDOW_HEIGHT = 500



def resource_path(relative_path):
    """Kullanılacak kaynak dosyalarının (resim) yolunu döndürür."""
    if os.path.isabs(relative_path):
        return relative_path

    if getattr(sys, 'frozen', False):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.abspath(os.path.dirname(sys.argv[0]))
    
    return os.path.join(base_path, relative_path)

# --- GERÇEK İŞLEM YÜRÜTÜCÜ SINIF (Operasyon Mantığı) ---
class OperationThread(QThread):
    """Uzun süreli işlemleri (Hash, ddrescue) ana iş parçacığından bağımsız yürütür."""
    output_update = pyqtSignal(str)
    progress_update = pyqtSignal(int) 
    # finished_signal sadece başarılı bir akış sonunda yayılacaktır
    finished_signal = pyqtSignal() 
    error_signal = pyqtSignal(str) 

    def __init__(self, operation_type, source, target):
        super().__init__()
        self.operation_type = operation_type
        self.source = source
        self.target = target
        self.is_running = True
        # ddrescue log dosyası /tmp'de tutulur
        self.log_file = os.path.join('/tmp', f"sysbackres_log_{os.getpid()}.log") 

    def stop(self):
        """İşlemi durdurma sinyali gönderir."""
        self.is_running = False

    def run(self):
        self.output_update.emit(f"[{time.strftime('%H:%M:%S')}] Operasyon Tipi: {self.operation_type}")
        self.output_update.emit(f"[{time.strftime('%H:%M:%S')}] Kaynak: {self.source}, Hedef: {self.target}")
        self.output_update.emit("--------------------------------------------------")

        success = False # Başarı durumunu takip etmek için yeni bayrak

        try:
            if self.operation_type == 'BACKUP_IMAGE':
                success = self._execute_backup_image_flow()
            elif self.operation_type in ['BACKUP_CLONE', 'RESTORE_DISK_TO_DISK', 'RESTORE_IMAGE_TO_DISK', 'VERIFY_TWO_DISKS']:
                success = self._execute_ddrescue_flow()
            elif self.operation_type == 'VERIFY_IMAGE':
                success = self._execute_image_verify_flow()
            else:
                self.error_signal.emit(lang.get('unknown_operation_type_error'))
                success = False # Hata oluştu

        except InterruptedError:
            # Kullanıcı durdurdu
            success = False 
            pass
        except Exception as e:
            self.error_signal.emit(lang.get('critical_operation_error').format(e))
            success = False

        # Sadece başarılı bir akış sonunda sinyal gönder
        if success:
            self.finished_signal.emit()

    # --- YARDIMCI METOTLAR ---

    def _parse_disk_selection(self, selection):
        """'/dev/sda (Model - Size)' -> '/dev/sda'"""
        if selection and selection.startswith('/dev/'):
            return selection.split(' ')[0]
        return selection

    def _get_disk_size(self, dev_path):
        """Disk/Dosya boyutunu byte cinsinden döndürür (Progress tahmini için)."""
        # Dosya boyutu
        if os.path.exists(dev_path) and os.path.isfile(dev_path):
            return os.path.getsize(dev_path)
        
        # Disk boyutu (root olmadan lsblk çalışır)
        if dev_path.startswith('/dev/'):
            try:
                cmd = ['lsblk', '-b', '-n', '-o', 'SIZE', dev_path]
                result = subprocess.run(cmd, capture_output=True, text=True, check=True)
                return int(result.stdout.strip())
            except Exception:
                pass
        return 0
        
    def _execute_command_blocking(self, cmd, description):
        """Basit (Progress gerektirmeyen) pkexec komutlarını çalıştırır ve çıktıyı akıtır."""
        # --- PKEXEC KULLANIMI BAŞLANGIÇ ---
        self.output_update.emit(f"[{time.strftime('%H:%M:%S')}] {description} Komut: {' '.join(['pkexec'] + cmd)}")
        full_cmd = ['pkexec'] + cmd 
        # --- PKEXEC KULLANIMI SONU ---
        
        try:
            # pkexec şifre sorgusunu GUI ile halleder, biz sadece komutun normal çıktısını yakalarız
            process = subprocess.Popen(full_cmd, 
                                       stdout=subprocess.PIPE, 
                                       stderr=subprocess.STDOUT, # stderr'i stdout'a yönlendir
                                       text=True, 
                                       encoding='utf-8')
            
            output_lines = [] 

            while True:
                line = process.stdout.readline()
                if line:
                    self.output_update.emit(line.strip())
                    output_lines.append(line) 
                
                if process.poll() is not None:
                    break
                
                if not self.is_running:
                    # İşlemi sonlandırma
                    process.terminate()
                    raise InterruptedError()
            
            full_output = "".join(output_lines) 

            if process.returncode != 0:
                raise subprocess.CalledProcessError(process.returncode, ' '.join(full_cmd))
            
            self.output_update.emit(f"[{time.strftime('%H:%M:%S')}] {description} BAŞARILI.")
            return full_output.strip() 

        except subprocess.CalledProcessError as e:
            self.error_signal.emit(f"{description} HATA! Kod: {e.returncode}. \nKomut: {e.cmd}")
            return None
        except FileNotFoundError:
             # Eğer komut bulunamadıysa (sha512sum veya ddrescue gibi)
             komut = full_cmd[1] if len(full_cmd) > 1 else "Bilinmeyen"
             self.error_signal.emit(f"HATA: {komut} komutu bulunamadı. Lütfen yükleyin.")
             return None
        except InterruptedError:
             self.output_update.emit(f"[{time.strftime('%H:%M:%S')}] {description} DURDURULDU.")
             return None
        except Exception as e:
             # KRİTİK HATA: Bilinmeyen Hata
             self.error_signal.emit(f"Bilinmeyen Hata ({description}): '{e}'")
             return None

    # --- PROGRESS BAR İLE DDRESCUE YÜRÜTME ---
    def _execute_ddrescue_with_progress(self, cmd, description, total_size):
        """ddrescue komutunu pkexec ile çalıştırır, çıktıyı parse eder ve progress'i günceller."""
        
        self.output_update.emit(f"[{time.strftime('%H:%M:%S')}] {description} Komut: {' '.join(['pkexec'] + cmd)}")
        full_cmd = ['pkexec'] + cmd 
        
        # ddrescue'un log dosyasından okunan ilerleme
        progress_re = re.compile(r'rescued:\s*(\d+)\s*B.*size:\s*(\d+)\s*B')

        try:
            process = subprocess.Popen(full_cmd, 
                                       stdout=subprocess.PIPE, 
                                       stderr=subprocess.STDOUT, 
                                       text=True, 
                                       encoding='utf-8')
            
            while True:
                # Non-blocking okuma
                line = process.stdout.readline()
                
                if line:
                    self.output_update.emit(line.strip())
                    
                    # Progress Parsing
                    match = progress_re.search(line)
                    if match:
                        rescued_bytes = int(match.group(1))
                        
                        if total_size > 0:
                            percentage = int((rescued_bytes / total_size) * 100)
                            if percentage > 100: percentage = 99 
                            self.progress_update.emit(percentage) 
                        
                if process.poll() is not None:
                    break
                
                # İşlem durdurulma kontrolü
                if not self.is_running:
                    # ddrescue'a sonlandırma sinyali gönder
                    process.terminate() 
                    raise InterruptedError()
            
            # Son kontrol ve başarı sinyali
            self.progress_update.emit(99) 

            if process.returncode != 0:
                raise subprocess.CalledProcessError(process.returncode, ' '.join(full_cmd))
            
            self.progress_update.emit(100) 
            self.output_update.emit(f"[{time.strftime('%H:%M:%S')}] {description} BAŞARILI.")
            return True

        except subprocess.CalledProcessError as e:
            msg = f"{description} HATA! Kod: {e.returncode}. \nKomut: {e.cmd}"
            self.error_signal.emit(msg)
            return False
        except FileNotFoundError:
             komut = full_cmd[1] if len(full_cmd) > 1 else "Bilinmeyen"
             self.error_signal.emit(f"HATA: {komut} komutu bulunamadı. Lütfen yükleyin.")
             return False
        except InterruptedError:
             self.output_update.emit(f"[{time.strftime('%H:%M:%S')}] {description} KULLANICI TARAFINDAN DURDURULDU.")
             self.progress_update.emit(0)
             return False
        except Exception as e:
             self.error_signal.emit(f"Bilinmeyen Hata ({description}): {e}")
             return False
             
    # --- YENİ HASH HESAPLAMA FONKSİYONU (SADECE DOSYALAR İÇİN GÜVENLİ) ---
    def _calculate_file_hash(self, filepath, hash_algo='sha512', block_size=65536):
        """Dosyanın hash değerini (varsayılan sha512) hesaplar. Disk aygıtları için kullanılmamalıdır."""
        self.output_update.emit(f"[{time.strftime('%H:%M:%S')}] Hash Hesaplama: {filepath} ({hash_algo})")
        
        # Dosya veya disk yolu var mı kontrol et
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Dosya/Aygıt bulunamadı: {filepath}")
        
        # UYARI: Eğer /dev/ ile başlıyorsa, bu metot YETKİ HATASI verecektir.
        if filepath.startswith('/dev/'):
            # Bu durumun, sadece VERIFY_IMAGE (yani normal dosya) akışında kullanılması beklenir.
            # Normal diskler için _execute_backup_image_flow içindeki sha512sum kullanılır.
            self.output_update.emit(f"[{time.strftime('%H:%M:%S')}] UYARI: Disk aygıtı için dahili Python hash hesaplama kullanılıyor. Yetki sorunu yaşanabilir.")
            
        hasher = hashlib.new(hash_algo)
        
        file_size = self._get_disk_size(filepath)
        
        try:
            with open(filepath, 'rb') as afile:
                buf = afile.read(block_size)
                total_read = 0
                while len(buf) > 0:
                    if not self.is_running:
                        raise InterruptedError("Kullanıcı tarafından durduruldu")
                        
                    hasher.update(buf)
                    total_read += len(buf)
                    
                    if file_size > 0:
                         percentage = int((total_read / file_size) * 100)
                         if percentage % 5 == 0:
                             self.progress_update.emit(percentage) 
                             
                    buf = afile.read(block_size)

            self.progress_update.emit(100) # Son olarak 100 yap
            return hasher.hexdigest()
            
        except FileNotFoundError as e:
            self.error_signal.emit(f"Hata: Dosya bulunamadı: {e}")
            return None
        except InterruptedError:
            raise
        except Exception as e:
            # KRİTİK HATA: Burası artık yetki hatasının yakalanacağı yerdir.
            self.error_signal.emit(f"Hash hesaplama sırasında kritik hata: [Errno {e.errno}] Erişim engellendi: '{filepath}'" if hasattr(e, 'errno') and e.errno == 13 else f"Hash hesaplama sırasında kritik hata: {e}")
            return None


    # --- ANA OPERASYON AKIŞLARI ---

    def _execute_backup_image_flow(self):
        """Disk -> İmaj operasyonu (Hash hesapla ve Klonla)."""
        source_dev = self._parse_disk_selection(self.source)
        target_path = self.target 
        hash_file_path = target_path + ".sha512" 
        
        # 1. Kaynak Diskin SHA Hash'ini Oluştur
        self.output_update.emit(f"[{time.strftime('%H:%M:%S')}] Adım 1/2: Kaynak disk için SHA512 hash oluşturuluyor...")
        
        # --- DÜZELTME: PKEXEC kullanarak sha512sum ile hash hesaplama ---
        self.output_update.emit(f"[{time.strftime('%H:%M:%S')}] Hash Hesaplama (pkexec sha512sum): {source_dev}")
        
        # sha512sum komutu, _execute_command_blocking ile pkexec aracılığıyla çalışır.
        # Bu, yetki hatasını önler.
        hash_result = self._execute_command_blocking(
            cmd=['sha512sum', source_dev], 
            description="SHA512 Hesaplama"
        )
        
        if hash_result is None:
            return False # Hata oluştu

        # sha512sum çıktısı: "hash_value  /dev/sdX"
        try:
             # İlk 2 boşluktan bölerek sadece hash değerini al
             parts = hash_result.split('  ')
             hash_value = parts[0].strip()
             
        except Exception:
             self.error_signal.emit("SHA512 Hesaplama çıktısı çözümlenemedi.")
             return False
        # --- DÜZELTME SONU ---
            
        # --- SHA HASH ÇIKTISINI DÜZENLEME ---
        try:
             # Hedef dizini oluştur (Boş dosya sorununu engeller)
             os.makedirs(os.path.dirname(target_path) or '.', exist_ok=True)
             
             image_filename = os.path.basename(target_path) 
             # Hash değeri, 2 boşluk ve dosya adı (sha512sum'un formatı)
             verification_hash_content = f"{hash_value}  {image_filename}\n" 

             # Hash'i dosyaya yaz (Kullanıcının dizininde olduğu için yetki sorunu olmaz)
             with open(hash_file_path, "w") as f:
                 f.write(verification_hash_content)
             self.output_update.emit(f"[{time.strftime('%H:%M:%S')}] SHA hash ({hash_value[:8]}...) başarıyla {hash_file_path} dosyasına yazıldı.")
             
        except Exception as e:
            self.error_signal.emit(f"SHA512 Hesaplama/Yazma sırasında hata: {e}")
            return False
            
        self.output_update.emit("--------------------------------------------------")

        # 2. Disk Klonlama (İmaj Oluşturma)
        self.output_update.emit(f"[{time.strftime('%H:%M:%S')}] Adım 2/2: Disk klonlama (imaj oluşturma) işlemi başlatılıyor...")
        
        source_size = self._get_disk_size(source_dev)
        ddrescue_cmd = ['ddrescue', '-f', '-v', source_dev, target_path, self.log_file] 
        
        if not self._execute_ddrescue_with_progress(ddrescue_cmd, "Disk İmajı Oluşturma", source_size):
            return False # ddrescue başarısız olursa False döndür
        
        self.output_update.emit(f"[{time.strftime('%H:%M:%S')}] İmaj oluşturma işlemi tamamlandı.")
        return True # Tüm adımlar başarılı

    def _execute_ddrescue_flow(self):
        """Diskten Diske Klonlama, Kurtarma veya Doğrulama akışı (ddrescue kullanılarak)."""
        source_dev = self._parse_disk_selection(self.source)
        target_dev = self._parse_disk_selection(self.target)
        
        description = "Disk Operasyonu"
        
        if self.operation_type == 'VERIFY_TWO_DISKS':
             ddrescue_cmd = ['ddrescue', '--compare', source_dev, target_dev]
             description = "İki Disk Doğrulama"
             # Karşılaştırma için hedef diskin boyutunu al
             total_size = self._get_disk_size(target_dev) 
             
        else:
             ddrescue_cmd = ['ddrescue', '-f', '-v', source_dev, target_dev, self.log_file] 
             description = "Disk Klonlama/Kurtarma"
             total_size = self._get_disk_size(source_dev)
        
        if not self._execute_ddrescue_with_progress(ddrescue_cmd, description, total_size):
            return False # ddrescue başarısız olursa False döndür
        
        self.output_update.emit(f"[{time.strftime('%H:%M:%S')}] Operasyon başarıyla tamamlandı.")
        return True # Başarılı

    def _execute_image_verify_flow(self):
        """İmaj Doğrulama akışı (Hashlib ile)."""
        image_path = self.source # Kaynak, İmaj Dosyası
        hash_file_path = self.target # Hedef, SHA512 Dosyası
        
        self.output_update.emit(f"[{time.strftime('%H:%M:%S')}] İmaj Dosyası ({image_path}) Bütünlük Kontrolü başlatılıyor...")
        
        if not os.path.exists(hash_file_path):
             self.error_signal.emit(f"HATA: Karşılaştırma için .sha512 dosyası bulunamadı: {hash_file_path}")
             return False # Hata
             
        # 1. SHA512 Dosyasından beklenen hash değerini oku
        expected_hash = None
        expected_filename = None
        try:
             with open(hash_file_path, "r") as f:
                 hash_content = f.read().strip()
                 # sha512sum formatı: hash_degeri  dosya_adi
                 parts = hash_content.split('  ')
                 if len(parts) == 2:
                      expected_hash = parts[0].strip()
                      expected_filename = parts[1].strip()
                      self.output_update.emit(f"[{time.strftime('%H:%M:%S')}] .sha512 içeriği: Hash={expected_hash[:8]}..., Dosya Adı={expected_filename}")
                 else:
                      self.error_signal.emit(f"HATA: .sha512 dosyası beklenmeyen formatta: {hash_content}")
                      return False
                      
        except Exception as e:
             self.error_signal.emit(f"HATA: .sha512 dosyasını okuyamadım: {e}")
             return False
             
        # 2. İmaj Dosyasının mevcut hash değerini hesapla
        try:
             # image_path normal bir dosya olduğu için dahili Python fonksiyonu kullanılır.
             calculated_hash = self._calculate_file_hash(image_path)
             if calculated_hash is None:
                 return False
                 
             self.output_update.emit(f"[{time.strftime('%H:%M:%S')}] Hesaplanan Hash: {calculated_hash[:8]}...")
             
        except InterruptedError:
             self.output_update.emit(f"[{time.strftime('%H:%M:%S')}] Hash Hesaplama KULLANICI TARAFINDAN DURDURULDU.")
             self.progress_update.emit(0)
             return False
        except Exception as e:
             # Bu hata artık normal dosyaların okunmasıyla ilgili olmalıdır, yetki değil.
             self.error_signal.emit(f"Hash hesaplama sırasında hata: {e}")
             return False
             
        # 3. Karşılaştır
        if calculated_hash.lower() == expected_hash.lower():
             self.output_update.emit(f"[{time.strftime('%H:%M:%S')}] Bütünlük Kontrolü Başarılı: İmaj sağlam.")
             return True
        else:
             self.error_signal.emit("KRİTİK HATA: Hash Doğrulama BAŞARISIZ! İmaj bozuk veya değiştirilmiş olabilir.")
             self.error_signal.emit(f"Beklenen Hash: {expected_hash}")
             self.error_signal.emit(f"Hesaplanan Hash: {calculated_hash}")
             return False


# --- Ana Pencere Sınıfı ---
class SystemBackupWizard(QMainWindow):
    def __init__(self):
        super().__init__()
        
        self.setWindowTitle("SysBackRes")
        icon_path = resource_path("icons/sysbackres.png")
        self.setWindowIcon(QIcon(icon_path))
        self.setFixedSize(WINDOW_WIDTH, WINDOW_HEIGHT) 
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowMaximizeButtonHint)

        self.current_page_index = 0
        self.last_operation_index = 2 
        self.selected_operation_type = 'BACKUP_IMAGE' 
        
        self.source_selection = ""
        self.target_selection = ""

        self.AVAILABLE_DISKS = [] 
        
        # --- KRİTİK HATA DÜZELTMESİ: QLineEdit nesnelerini önceden tanımlama ---
        self.source_path_edit = None
        self.target_path_edit_save = None
        self.target_path_edit_open = None
        # ---------------------------------------------------------------------

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        self.sidebar = self.setup_image_sidebar() 
        self.sidebar.setFixedWidth(IMAGE_WIDTH) 
        
        self.stacked_widget = QStackedWidget()
        self.stacked_widget.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        # Buton Alanı
        self.button_layout = QHBoxLayout()
        
        self.language_button = QPushButton("Language")
        self.language_button.clicked.connect(self.show_language_dialog)
        self.about_button = QPushButton(lang.get('about'))
        self.about_button.clicked.connect(self.show_about_dialog)
        
        self.back_button = QPushButton(lang.get('back'))
        self.back_button.clicked.connect(self.go_back)
        
        self.next_button = QPushButton(lang.get('next'))
        self.next_button.clicked.connect(self.go_next)
        
        self.exit_button = QPushButton(lang.get('exit'))
        self.exit_button.clicked.connect(self.close)
        
        self.button_layout.addWidget(self.language_button)
        self.button_layout.addWidget(self.about_button)
        self.button_layout.addStretch(1) 
        self.button_layout.addWidget(self.back_button) 
        self.button_layout.addWidget(self.next_button)
        self.button_layout.addWidget(self.exit_button)
        
        # Ana Layout Düzeni
        content_layout = QHBoxLayout()
        content_layout.addWidget(self.sidebar)
        content_layout.addWidget(self.stacked_widget)
        
        main_layout.addLayout(content_layout)
        main_layout.addLayout(self.button_layout)
        
        # Tüm Sayfaları Oluştur
        self.create_pages()
        
        self.stacked_widget.setCurrentIndex(self.current_page_index)
        self.update_buttons() 
            
    def closeEvent(self, event):
        """Pencere kapatıldığında iş parçacığını durdur."""
        if hasattr(self, 'op_thread') and self.op_thread.isRunning():
            self.op_thread.stop()
            self.op_thread.wait(2000) # 2 saniye bekle
        super().closeEvent(event)
            
    def setup_image_sidebar(self):
        """'leftpanel.png' resmini yan panelde gösterir."""
        image_container = QWidget()
        vbox = QVBoxLayout(image_container)
        vbox.setContentsMargins(0, 0, 0, 0)
        
        image_label = QLabel()
        image_path = resource_path("icons/leftpanel.png")
        
        pixmap = QPixmap(image_path)
        
        if not pixmap.isNull():
            scaled_pixmap = pixmap.scaled(IMAGE_WIDTH, WINDOW_HEIGHT, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            image_label.setPixmap(scaled_pixmap)
            image_label.setAlignment(Qt.AlignTop | Qt.AlignHCenter)
        else:
            image_label.setText("Resim Yüklenemedi (leftpanel.png)")
            image_label.setStyleSheet("background-color: #00BFFF; color: white; text-align: center;") 
            image_label.setAlignment(Qt.AlignCenter)
            image_label.setFixedSize(IMAGE_WIDTH, WINDOW_HEIGHT) 
            
        vbox.addWidget(image_label, alignment=Qt.AlignTop) 
        vbox.addStretch(1) 
        return image_container
            
    def update_window_title(self):
        self.setWindowTitle(lang.get('window_title'))
    
    def show_language_dialog(self):
        from PyQt5.QtWidgets import QDialog, QVBoxLayout, QDialogButtonBox, QLabel
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Language / Dil")
        dialog.setFixedSize(300, 150)
        
        layout = QVBoxLayout(dialog)
        
        # Dil seçimi etiketi
        label = QLabel("Select Language / Dil Seçin:")
        layout.addWidget(label)
        
        # ComboBox ile dil seçimi
        self.lang_combo = QComboBox()
        
        # Mevcut dilleri ComboBox'a ekle
        for lang_name in lang.available_languages:
            self.lang_combo.addItem(lang_name, lang_name)
            
            # Mevcut dili seçili yap
            if lang_name == lang.current_language:
                self.lang_combo.setCurrentIndex(self.lang_combo.count() - 1)
        
        layout.addWidget(self.lang_combo)
        
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        
        if dialog.exec_() == QDialog.Accepted:
            selected_lang = self.lang_combo.currentData()
            if selected_lang and selected_lang != lang.current_language:
                lang.set_language(selected_lang)
                self.update_all_texts()
    
    def update_all_texts(self):
        # Buton metinlerini güncelle
        self.about_button.setText(lang.get('about'))
        self.back_button.setText(lang.get('back'))
        self.exit_button.setText(lang.get('exit'))
        
        # Pencere başlığını güncelle
        self.update_window_title()
        
        # Mevcut sayfa başlığını güncelle
        current_page = self.stacked_widget.widget(self.current_page_index)
        if hasattr(current_page, 'page_title_label'):
            current_page.page_title_label.setText(lang.get('wizard_titles')[self.current_page_index])
        
        # Next butonunu güncelle
        if self.current_page_index == 6:
            if hasattr(self, 'op_thread') and self.op_thread.isRunning():
                self.next_button.setText(lang.get('stop_operation'))
            else:
                self.next_button.setText(lang.get('ok'))
        else:
            self.next_button.setText(lang.get('start') if self.current_page_index == 0 else lang.get('next'))
        
        # Tüm sayfaları yeniden oluştur
        self.recreate_pages()

    # --- LSBLK İLE DİSK TESPİTİ ---
    def get_disk_list_from_lsblk(self):
        """lsblk komutunu çalıştırarak sistemdeki YALNIZCA ana diskleri listeler (sda, sdb vb.)."""
        disk_list = []
        try:
            # lsblk, root yetkisi olmadan da çalışır.
            cmd = ['lsblk', '-J', '-b', '-o', 'NAME,SIZE,MODEL,RO,TYPE']
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            data = json.loads(result.stdout)
            
            for dev in data.get('blockdevices', []):
                # Sadece 'disk' tipindeki cihazları filtrele.
                if dev.get('name') and dev.get('type') == 'disk':
                    
                    # Boyutu daha okunabilir bir formata çevirme
                    size_bytes = int(dev.get('size', 0))
                    size_display = ""
                    if size_bytes > (1024**4): 
                        size_display = f"{size_bytes / (1024**4):.1f}T"
                    elif size_bytes > (1024**3): 
                        size_display = f"{size_bytes / (1024**3):.1f}G"
                    elif size_bytes > (1024**2): 
                        size_display = f"{size_bytes / (1024**2):.1f}M"
                    
                    model = dev.get('model', lang.get('unknown')).strip()
                    display_name = f"/dev/{dev['name']} ({model} - {size_display})"
                    disk_list.append(display_name)

        except subprocess.CalledProcessError as e:
            disk_list.append(f"(HATA: lsblk çalışmadı: {e.returncode})")
        except FileNotFoundError:
            disk_list.append("(HATA: lsblk bulunamadı, Lütfen Yükleyin.)")
        except json.JSONDecodeError:
            disk_list.append("(HATA: lsblk çıktısı çözümlenemedi.)")
        except Exception as e:
             disk_list.append(f"(Bilinmeyen Hata: {e})")
             
        return disk_list

    # --- YETKİ KONTROLÜ VE ALIMI (PKEXEC KULLANARAK) ---
    def check_and_acquire_root(self):
        """Root yetkisini kontrol eder."""
        
        if os.name != 'posix':
            QMessageBox.critical(self, lang.get('error'), lang.get('linux_only_error'))
            return False
        
        if os.geteuid() == 0:
            # Zaten root yetkisiyle çalışıyorsa (çok nadir)
            return True
        
        # Uyarı mesajı kaldırıldı, direkt True döndür
        return True 

    # --- DOSYA DİYALOG METOTLARI (DÜZELTİLDİ) ---
    
    def select_backup_image_path(self):
        """Yedek imaj dosyasının kaydedileceği konumu seçer (Save Dialog)."""
        # Hata düzeltme: Doğru QLineEdit nesnesini kullan ve None kontrolü yap.
        editor = self.target_path_edit_save 
        if editor is None: return 
        
        default_name = os.path.basename(editor.text() or "yedek.img")
        start_dir = os.path.dirname(editor.text()) if editor.text() and os.path.isdir(os.path.dirname(editor.text())) else os.path.expanduser("~")
        
        file_path, _ = QFileDialog.getSaveFileName(self, 
                                                   lang.get('select_backup_image_location'), 
                                                   os.path.join(start_dir, default_name), 
                                                   lang.get('image_file_filter'))
        if file_path:
            editor.setText(file_path)
            self.update_selection_variables()

    def select_existing_image_file(self):
        """Mevcut imaj dosyasını seçer (Open Dialog)."""
        # Hata düzeltme: Doğru QLineEdit nesnesini kullan ve None kontrolü yap.
        editor = self.source_path_edit
        if editor is None: return
        
        start_dir = os.path.dirname(editor.text()) if editor.text() and os.path.isdir(os.path.dirname(editor.text())) else os.path.expanduser("~")
        
        file_path, _ = QFileDialog.getOpenFileName(self, 
                                                  lang.get('select_existing_image'), 
                                                  start_dir, 
                                                  "Disk İmaj Dosyaları (*.img *.iso *.bin);;Tüm Dosyalar (*)")
        if file_path:
            editor.setText(file_path)
            self.update_selection_variables()
            
    def select_sha512_file(self):
        """Mevcut .sha512 doğrulama dosyasını seçer (Open Dialog)."""
        # Hata düzeltme: Doğru QLineEdit nesnesini kullan ve None kontrolü yap.
        editor = self.target_path_edit_open
        if editor is None: return

        start_dir = os.path.dirname(editor.text()) if editor.text() and os.path.isdir(os.path.dirname(editor.text())) else os.path.expanduser("~")
        
        file_path, _ = QFileDialog.getOpenFileName(self, 
                                                  lang.get('select_existing_sha512'), 
                                                  start_dir, 
                                                  lang.get('sha512_file_filter'))
        if file_path:
            editor.setText(file_path)
            self.update_selection_variables()


    # --- AKIŞ KONTROLÜ ---

    def update_buttons(self):
        current = self.current_page_index
        
        self.update_window_title() 
        
        current_page = self.stacked_widget.widget(current)
        if hasattr(current_page, 'page_title_label'):
             current_page.page_title_label.setText(lang.get('wizard_titles')[current])

        self.back_button.setVisible(current > 0)
        self.back_button.setEnabled(current > 0)
        
        if current == 6: 
            if hasattr(self, 'op_thread') and self.op_thread.isRunning():
                 self.next_button.setText(lang.get('stop_operation'))
            else:
                 self.next_button.setText(lang.get('ok'))
            self.next_button.setEnabled(True) 
        else:
            self.next_button.setText(lang.get('start') if current == 0 else lang.get('next'))
            self.next_button.setEnabled(True)
            
        if current == 5:
            self.update_selection_options() 
            self.update_details_page_visuals()

    def go_next(self):
        current = self.current_page_index
        next_index = -1 

        if current == 0:  next_index = 1 
        elif current == 1:  
            if self.radio_backup.isChecked(): next_index = 2; self.last_operation_index = 2 
            elif self.radio_restore.isChecked(): next_index = 3; self.last_operation_index = 3 
            elif self.radio_verify.isChecked(): next_index = 4; self.last_operation_index = 4 
            else: return 
        
        elif current == 2: 
            # DİKKAT: Sıralama değişti: Önce İmaj Oluştur, sonra Klonla
            if self.radio_create_image.isChecked(): self.selected_operation_type = 'BACKUP_IMAGE'
            elif self.radio_clone.isChecked(): self.selected_operation_type = 'BACKUP_CLONE' 
            next_index = 5 
        
        elif current == 3: 
            if self.radio_restore_img_to_disk.isChecked(): self.selected_operation_type = 'RESTORE_IMAGE_TO_DISK' 
            elif self.radio_restore_disk_to_disk.isChecked(): self.selected_operation_type = 'RESTORE_DISK_TO_DISK' 
            next_index = 5 
        
        elif current == 4: 
            if self.radio_verify_image.isChecked(): self.selected_operation_type = 'VERIFY_IMAGE' 
            elif self.radio_verify_two_disks.isChecked(): self.selected_operation_type = 'VERIFY_TWO_DISKS' 
            next_index = 5 

        elif current == 5: 
            if not self.check_valid_selections(): return
            
            self.start_operation_sequence()
            next_index = 6

        elif current == 6: 
            if hasattr(self, 'op_thread') and self.op_thread.isRunning():
                self.op_thread.stop()
                self.progress_bar.setRange(0, 100)
                self.progress_bar.setValue(0)
                
                self.next_button.setText(lang.get('stopping'))
                self.next_button.setEnabled(False)
                QTimer.singleShot(500, self.check_thread_stop)
                return 

            self.go_finish() 
            return
        
        if next_index != -1:
            self.current_page_index = next_index
            self.stacked_widget.setCurrentIndex(self.current_page_index)
            self.update_buttons()
            
    def check_thread_stop(self):
        """İş parçacığının durup durmadığını kontrol eder ve kullanıcıyı bilgilendirir."""
        if hasattr(self, 'op_thread') and not self.op_thread.isRunning():
            QMessageBox.information(self, lang.get('info'), lang.get('operation_stopped'))
            self.next_button.setText(lang.get('ok'))
            self.next_button.setEnabled(True)
        elif hasattr(self, 'op_thread'):
             QTimer.singleShot(500, self.check_thread_stop)
        else:
             self.next_button.setText(lang.get('ok'))
             self.next_button.setEnabled(True)

    def go_back(self):
        current = self.current_page_index
        prev_index = -1 

        if current == 0: return 
        elif current == 1: prev_index = 0 
        elif current in [2, 3, 4]: prev_index = 1 
        elif current == 5: prev_index = self.last_operation_index
        elif current == 6: prev_index = 5 

        if prev_index != -1:
            self.current_page_index = prev_index
            self.stacked_widget.setCurrentIndex(self.current_page_index)
            self.update_buttons()

    def go_finish(self):
        # Hoşgeldiniz ekranına dön
        self.current_page_index = 0
        self.stacked_widget.setCurrentIndex(self.current_page_index)
        self.update_buttons()

    # --- GEREKLİ KONTROLLER ---
    def check_valid_selections(self):
        if self.source_selection in [f"({lang.get('no_selection_made')})", ""]:
            QMessageBox.warning(self, lang.get('error'), lang.get('please_select_source'))
            return False
        
        # VERIFY_IMAGE hariç tüm operasyonlar için hedef seçimi kontrolü
        if self.selected_operation_type != 'VERIFY_IMAGE':
            if self.target_selection in [f"({lang.get('no_selection_made')})", f"({lang.get('target_not_required')})", ""]:
                QMessageBox.warning(self, lang.get('error'), lang.get('please_select_target'))
                return False
        else:
             # VERIFY_IMAGE için hedef, .sha512 dosyasıdır.
             if not self.target_selection or not self.target_selection.lower().endswith(".sha512"):
                 QMessageBox.warning(self, lang.get('error'), lang.get('please_select_valid_sha512'))
                 return False

        # Disk klonlama/yazma işlemleri için kaynak-hedef farklılık kontrolü
        source_dev_name = self.source_selection.split(' ')[0]
        target_dev_name = self.target_selection.split(' ')[0]
        
        # Disk operasyonu ise ve kaynak-hedef aynı ise hata ver
        if source_dev_name == target_dev_name and source_dev_name.startswith('/dev/'):
            QMessageBox.critical(self, lang.get('critical_error'), lang.get('source_target_same_error'))
            return False
            
        return True

    # --- İŞLEM BAŞLATMA SIRASI VE THREAD YÖNETİMİ ---
    def start_operation_sequence(self):
        """Asenkron işlem iş parçacığını başlatır ve ProgressBar'ı meşgul moda alır."""
        
        self.progress_bar.setRange(0, 0) 
        self.output_text_edit.clear()
        
        self.next_button.setText(lang.get('operation_in_progress'))
        self.next_button.setEnabled(False) 
        
        # VERIFY_IMAGE için target, SHA512 dosyasıdır.
        actual_target = self.target_selection
        
        self.op_thread = OperationThread(self.selected_operation_type, self.source_selection, actual_target)
        
        self.op_thread.output_update.connect(self.update_output)
        self.op_thread.progress_update.connect(self.update_progress_bar) 
        self.op_thread.error_signal.connect(self.operation_error) 
        self.op_thread.finished_signal.connect(self.operation_finished)
        
        self.op_thread.start()
        
    def update_output(self, text):
        self.output_text_edit.append(text)
        self.output_text_edit.ensureCursorVisible()
        
    def update_progress_bar(self, percentage):
        """İş parçacığından gelen ilerleme yüzdesini günceller."""
        if self.progress_bar.maximum() == 0:
            self.progress_bar.setRange(0, 100) 
            
        if percentage >= 0 and percentage <= 100:
            self.progress_bar.setValue(percentage)

    def operation_error(self, message):
        """İşlem sırasında bir hata oluşursa çalışır."""
        if hasattr(self, 'op_thread') and self.op_thread.isRunning():
            self.op_thread.stop()
        
        self.progress_bar.setRange(0, 100) 
        self.progress_bar.setValue(0) 
        
        self.output_text_edit.append("--------------------------------------------------")
        self.output_text_edit.append(f"KRİTİK HATA: {message}")
        
        self.next_button.setText(lang.get('ok'))
        self.next_button.setEnabled(True) 
        QMessageBox.critical(self, lang.get('error'), lang.get('operation_failed'))


    def operation_finished(self):
        """İşlem bitince çağrılır (Sadece başarılı akışta)."""
        self.progress_bar.setRange(0, 100) 
        self.progress_bar.setValue(100) 
        
        self.next_button.setText(lang.get('ok'))
        self.next_button.setEnabled(True) 
        
        self.show_completion_dialog()
        
    def show_completion_dialog(self):
        """İşlem bitti penceresini gösterir."""
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Information)
        msg.setText(lang.get('operation_completed_successfully'))
        msg.setInformativeText(lang.get('operation_completed_info').format(self.selected_operation_type))
        msg.setWindowTitle(lang.get('success'))
        msg.exec_()
        
    # --- Diğer Sayfa Oluşturma Metotları ---
    def create_pages(self):
        self.page_details = self.create_step3_details_page()
        
        self.stacked_widget.addWidget(self.create_step0_welcome_page())         
        self.stacked_widget.addWidget(self.create_step1_selection_page())       
        self.stacked_widget.addWidget(self.create_step2_backup_type_page())     
        self.stacked_widget.addWidget(self.create_step2_restore_type_page())    
        self.stacked_widget.addWidget(self.create_step2_verify_type_page())     
        self.stacked_widget.addWidget(self.page_details)         
        self.stacked_widget.addWidget(self.create_step4_process_page())
    
    def recreate_pages(self):
        # Mevcut sayfaları temizle
        while self.stacked_widget.count() > 0:
            widget = self.stacked_widget.widget(0)
            self.stacked_widget.removeWidget(widget)
            widget.deleteLater()
        
        # Sayfaları yeniden oluştur
        self.create_pages()
        
        # Mevcut sayfayı geri yükle
        self.stacked_widget.setCurrentIndex(self.current_page_index)
        
    def create_step0_welcome_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        
        page.page_title_label = QLabel(lang.get('wizard_titles')[0])
        page.page_title_label.setFont(QFont("Sanserif", 14, QFont.Bold))
        layout.addWidget(page.page_title_label)
        
        layout.addSpacing(30)
        
        welcome_text = QLabel(lang.get('welcome_text'))
        welcome_text.setWordWrap(True)
        layout.addWidget(welcome_text)

        layout.addSpacing(20)

        tech_info = QLabel(lang.get('tech_info'))
        tech_info.setWordWrap(True)
        layout.addWidget(tech_info)
        
        layout.addStretch(1)
        
        start_label = QLabel(lang.get('start_instruction'))
        start_label.setWordWrap(True)
        layout.addWidget(start_label)
        
        layout.addSpacing(15)
        return page
        
    def setup_option_widget(self, parent_layout, radio_button, description, icon_path):
        hbox = QHBoxLayout()
        icon_label = QLabel()
        
        ICON_SIZE = QSize(100, 100) 
        
        full_icon_path = resource_path("icons/" + icon_path)
        pixmap = QPixmap(full_icon_path)
        
        if not pixmap.isNull():
            icon_label.setPixmap(pixmap.scaled(ICON_SIZE, Qt.KeepAspectRatio, Qt.SmoothTransformation)) 
        else:
            icon_label.setText("X")
            icon_label.setStyleSheet("color: red; border: 1px solid red; qproperty-alignment: 'AlignCenter';")
            icon_label.setFixedSize(ICON_SIZE)
        
        hbox.addWidget(icon_label)
        
        vbox = QVBoxLayout()
        vbox.addWidget(radio_button)
        description_label = QLabel(description)
        description_label.setWordWrap(True) 
        vbox.addWidget(description_label)
        vbox.addSpacing(5) 
        
        hbox.addLayout(vbox)
        hbox.addStretch(1)
        parent_layout.addLayout(hbox)
        
    def create_step1_selection_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        
        page.page_title_label = QLabel(lang.get('wizard_titles')[1])
        page.page_title_label.setFont(QFont("Sanserif", 12, QFont.Bold))
        layout.addWidget(page.page_title_label)
        
        description_text = QLabel(lang.get('operation_selection_desc'))
        description_text.setWordWrap(True) 
        layout.addWidget(description_text)
        
        layout.addSpacing(45) 

        options_container = QWidget()
        options_layout = QVBoxLayout(options_container)
        options_layout.setSpacing(15) 

        self.radio_backup = QRadioButton(lang.get('backup'))
        self.setup_option_widget(options_layout, self.radio_backup, 
                                lang.get('backup_desc'),
                                "disktoimg.png")
        
        self.radio_restore = QRadioButton(lang.get('restore'))
        self.setup_option_widget(options_layout, self.radio_restore, 
                                lang.get('restore_desc'),
                                "imgtodisk.png")

        self.radio_verify = QRadioButton(lang.get('verify'))
        self.setup_option_widget(options_layout, self.radio_verify, 
                                lang.get('verify_desc'),
                                "verify.png")
        
        self.radio_backup.setChecked(True)
        layout.addWidget(options_container)
        layout.addStretch(1)
        return page

    def create_step2_backup_type_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        
        page.page_title_label = QLabel(lang.get('wizard_titles')[2])
        page.page_title_label.setFont(QFont("Sanserif", 12, QFont.Bold))
        layout.addWidget(page.page_title_label)
        
        description_text = QLabel(lang.get('backup_type_desc'))
        description_text.setWordWrap(True) 
        layout.addWidget(description_text)
        
        layout.addSpacing(45) 

        options_container = QWidget() 
        options_layout = QVBoxLayout(options_container)
        options_layout.setSpacing(15) 
        
        # SIRA DEĞİŞTİ: Disk İmaj Dosyası Oluştur en üste
        self.radio_create_image = QRadioButton(lang.get('create_image'))
        self.setup_option_widget(options_layout, self.radio_create_image,
                                lang.get('create_image_desc'),
                                "disktoimg.png")

        self.radio_clone = QRadioButton(lang.get('clone_disk'))
        self.setup_option_widget(options_layout, self.radio_clone,
                                lang.get('clone_disk_desc'),
                                "disktodisk.png")
        
        self.radio_create_image.setChecked(True) # Varsayılan da değişti
        layout.addWidget(options_container)
        layout.addStretch(1)
        return page

    def create_step2_restore_type_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        
        page.page_title_label = QLabel(lang.get('wizard_titles')[3])
        page.page_title_label.setFont(QFont("Sanserif", 12, QFont.Bold))
        layout.addWidget(page.page_title_label)
        
        description_text = QLabel(lang.get('restore_type_desc'))
        description_text.setWordWrap(True) 
        layout.addWidget(description_text)
        
        layout.addSpacing(45) 

        options_container = QWidget() 
        options_layout = QVBoxLayout(options_container)
        options_layout.setSpacing(15) 
        
        self.radio_restore_img_to_disk = QRadioButton(lang.get('restore_img_to_disk'))
        self.setup_option_widget(options_layout, self.radio_restore_img_to_disk,
                                lang.get('restore_img_to_disk_desc'),
                                "imgtodisk.png")
        
        self.radio_restore_disk_to_disk = QRadioButton(lang.get('restore_disk_to_disk'))
        self.setup_option_widget(options_layout, self.radio_restore_disk_to_disk,
                                lang.get('restore_disk_to_disk_desc'),
                                "disktodisk2.png")
        
        self.radio_restore_img_to_disk.setChecked(True)
        layout.addWidget(options_container)
        layout.addStretch(1)
        return page

    def create_step2_verify_type_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        
        page.page_title_label = QLabel(lang.get('wizard_titles')[4])
        page.page_title_label.setFont(QFont("Sanserif", 12, QFont.Bold))
        layout.addWidget(page.page_title_label)
        
        description_text = QLabel("Hangi tür bir doğrulama işlemi yapmak istiyorsunuz? Tek bir imajın bütünlüğünü mı kontrol edeceksiniz, yoksa iki diskin tamamen aynı olup olmadığını mı sınayacaksınız?")
        description_text.setWordWrap(True) 
        layout.addWidget(description_text)
        
        layout.addSpacing(45) 

        options_container = QWidget() 
        options_layout = QVBoxLayout(options_container)
        options_layout.setSpacing(15) 
        
        self.radio_verify_image = QRadioButton(lang.get('verify_image'))
        self.setup_option_widget(options_layout, self.radio_verify_image,
                                lang.get('verify_image_desc'),
                                "verifyimg.png") 
        
        self.radio_verify_two_disks = QRadioButton(lang.get('verify_two_disks'))
        self.setup_option_widget(options_layout, self.radio_verify_two_disks,
                                lang.get('verify_two_disks_desc'),
                                "verifydisks.png") 
        
        self.radio_verify_image.setChecked(True)
        layout.addWidget(options_container)
        layout.addStretch(1)
        return page
    
    def create_step3_details_page(self):
        """Index 5: Kaynak ve Hedef disk/dosya seçimi (Ortak Adım 3)."""
        page = QWidget()
        layout = QVBoxLayout(page)
        
        page.page_title_label = QLabel(lang.get('wizard_titles')[5])
        page.page_title_label.setFont(QFont("Sanserif", 12, QFont.Bold))
        layout.addWidget(page.page_title_label)
        
        description_text = QLabel(lang.get('details_desc'))
        description_text.setWordWrap(True) 
        layout.addWidget(description_text)
        
        layout.addSpacing(15) 
        
        disk_selection_group = QGroupBox(lang.get('selections')) 
        grid_layout = QGridLayout(disk_selection_group)
        grid_layout.setVerticalSpacing(10) 
        
        # --- KAYNAK SEÇİM ALANI (DISK COMBO vs DOSYA SATIRI) ---
        grid_layout.addWidget(QLabel(lang.get('source_disk_file')), 0, 0)
        
        self.source_stacked_widget = QStackedWidget()
        
        # 1. Kaynak ComboBox (StackedWidget Index 0) - Disk seçimi
        self.source_disk_combo = QComboBox()
        self.source_disk_combo.currentTextChanged.connect(self.update_selection_variables)
        self.source_stacked_widget.addWidget(self.source_disk_combo)

        # 2. Kaynak QLineEdit + QPushButton (StackedWidget Index 1) - Dosya seçimi (İmaj dosyası)
        source_hbox = QHBoxLayout()
        source_hbox.setContentsMargins(0, 0, 0, 0) 
        
        self.source_path_edit = QLineEdit() # __init__'te None atanmıştı, şimdi burada QLineEdit nesnesi atanır
        self.source_path_edit.setPlaceholderText(lang.get('select_existing_image_placeholder'))
        self.source_path_edit.textChanged.connect(self.update_selection_variables)
        
        self.source_browse_button = QPushButton(lang.get('browse'))
        self.source_browse_button.clicked.connect(self.select_existing_image_file) 
        source_hbox.addWidget(self.source_path_edit)
        source_hbox.addWidget(self.source_browse_button)
        
        self.source_file_widget = QWidget()
        self.source_file_widget.setLayout(source_hbox)
        self.source_stacked_widget.addWidget(self.source_file_widget)
        
        grid_layout.addWidget(self.source_stacked_widget, 0, 1) 

        # --- HEDEF SEÇİM ALANI (DISK COMBO vs DOSYA SATIRI) ---
        
        self.target_label = QLabel(lang.get('target_disk_file'))
        grid_layout.addWidget(self.target_label, 1, 0)
        
        self.target_stacked_widget = QStackedWidget()

        # 1. Hedef ComboBox (StackedWidget Index 0) - Disk seçimi
        self.target_disk_combo = QComboBox()
        self.target_disk_combo.currentTextChanged.connect(self.update_selection_variables)
        self.target_stacked_widget.addWidget(self.target_disk_combo) 

        # 2. Hedef QLineEdit + QPushButton (StackedWidget Index 1) - Dosya kaydetme (Yeni İmaj Dosyası)
        target_hbox_save = QHBoxLayout()
        target_hbox_save.setContentsMargins(0, 0, 0, 0)
        
        self.target_path_edit_save = QLineEdit() # __init__'te None atanmıştı, şimdi burada QLineEdit nesnesi atanır
        self.target_path_edit_save.setPlaceholderText(lang.get('create_image_placeholder'))
        self.target_path_edit_save.textChanged.connect(self.update_selection_variables)
        
        self.target_browse_button_save = QPushButton(lang.get('browse'))
        self.target_browse_button_save.clicked.connect(self.select_backup_image_path) 
        target_hbox_save.addWidget(self.target_path_edit_save)
        target_hbox_save.addWidget(self.target_browse_button_save)
        
        self.target_file_save_widget = QWidget()
        self.target_file_save_widget.setLayout(target_hbox_save)
        self.target_stacked_widget.addWidget(self.target_file_save_widget)
        
        # 3. Hedef QLineEdit + QPushButton (StackedWidget Index 2) - Dosya açma (SHA512 Dosyası)
        target_hbox_open = QHBoxLayout()
        target_hbox_open.setContentsMargins(0, 0, 0, 0)
        
        self.target_path_edit_open = QLineEdit() # __init__'te None atanmıştı, şimdi burada QLineEdit nesnesi atanır
        self.target_path_edit_open.setPlaceholderText(lang.get('select_sha512_placeholder'))
        self.target_path_edit_open.textChanged.connect(self.update_selection_variables)
        
        self.target_browse_button_open = QPushButton(lang.get('browse'))
        self.target_browse_button_open.clicked.connect(self.select_sha512_file) 
        target_hbox_open.addWidget(self.target_path_edit_open)
        target_hbox_open.addWidget(self.target_browse_button_open)
        
        self.target_file_open_widget = QWidget()
        self.target_file_open_widget.setLayout(target_hbox_open)
        self.target_stacked_widget.addWidget(self.target_file_open_widget)
        
        grid_layout.addWidget(self.target_stacked_widget, 1, 1) 
        
        layout.addWidget(disk_selection_group)
        layout.addSpacing(15) 
        
        # --- Görselleştirme Alanı ---
        self.diagram_label = QLabel(f"<b>{lang.get('operation_status')}:</b>")
        self.diagram_label.setFont(QFont("Sanserif", 10, QFont.Bold))
        layout.addWidget(self.diagram_label)
        
        self.image_display_widget = QWidget()
        self.image_layout = QVBoxLayout(self.image_display_widget)
        self.image_layout.setAlignment(Qt.AlignCenter) 
        self.image_layout.setContentsMargins(0, 5, 0, 0)

        self.operation_image_label = QLabel()
        self.operation_image_label.setAlignment(Qt.AlignCenter)
        self.image_layout.addWidget(self.operation_image_label)
        
        text_hbox = QHBoxLayout()
        self.source_text_label = QLabel(f"{lang.get('source')}: {lang.get('not_selected')}")
        self.source_text_label.setAlignment(Qt.AlignLeft)
        
        self.target_text_label = QLabel(f"{lang.get('target')}: {lang.get('not_selected')}")
        self.target_text_label.setAlignment(Qt.AlignRight)
        
        text_hbox.addWidget(self.source_text_label)
        text_hbox.addStretch(1)
        text_hbox.addWidget(self.target_text_label)
        
        self.image_layout.addLayout(text_hbox)
        
        layout.addWidget(self.image_display_widget)
        
        layout.addStretch(1)
        
        self.update_selection_variables() 
        self.update_details_page_visuals()

        return page
        
    def update_selection_variables(self):
        """Kullanıcının seçtiği disk/dosya adlarını (ComboBox veya QLineEdit'ten) kaydeder."""
        
        # Kaynak seçimi 
        if self.source_stacked_widget.currentIndex() == 0:
            self.source_selection = self.source_disk_combo.currentText()
        elif self.source_stacked_widget.currentIndex() == 1:
            # None kontrolü gerekli değildir, çünkü burada sadece değeri okuyoruz.
            self.source_selection = self.source_path_edit.text().strip() if self.source_path_edit else ""
        else:
            self.source_selection = ""

        # Hedef seçimi
        if self.target_stacked_widget.currentIndex() == 0: # Disk Seçimi
            self.target_selection = self.target_disk_combo.currentText()
        elif self.target_stacked_widget.currentIndex() == 1: # Dosya Kaydetme (İmaj Oluşturma)
             # None kontrolü gerekli değildir, çünkü burada sadece değeri okuyoruz.
             self.target_selection = self.target_path_edit_save.text().strip() if self.target_path_edit_save else ""
        elif self.target_stacked_widget.currentIndex() == 2: # Dosya Açma (SHA512)
             # None kontrolü gerekli değildir, çünkü burada sadece değeri okuyoruz.
             self.target_selection = self.target_path_edit_open.text().strip() if self.target_path_edit_open else ""
        else:
            self.target_selection = "" 
            

        def format_display_name(selection):
            if not selection or selection in [f"({lang.get('no_selection_made')})"]:
                return lang.get('not_selected')
            
            # Eğer /dev/ ile başlıyorsa sadece cihaz adını göster
            if selection.startswith('/dev/'):
                return selection.split(" ")[0]
            
            # Eğer dosya yolu ise sadece dosya adını göster
            if '/' in selection:
                 return os.path.basename(selection)

            return selection

        # Metin düzenlemesi
        self.source_text_label.setText(f"{lang.get('source')}: <b>{format_display_name(self.source_selection)}</b>")
        self.target_text_label.setText(f"{lang.get('target')}: <b>{format_display_name(self.target_selection)}</b>")


    def update_selection_options(self):
        """Seçilen operasyon tipine göre Kaynak ve Hedef widget'larını ayarlar."""
        
        self.AVAILABLE_DISKS = self.get_disk_list_from_lsblk()
        
        op_type = self.selected_operation_type
        
        # --- KAYNAK (Source) AYARLARI ---
        if op_type in ['BACKUP_CLONE', 'RESTORE_DISK_TO_DISK', 'VERIFY_TWO_DISKS', 'BACKUP_IMAGE']: 
            self.source_stacked_widget.setCurrentIndex(0) # Disk Combo
            source_options = [f"({lang.get('no_selection_made')})"]
            source_options.extend(self.AVAILABLE_DISKS)
            self.source_disk_combo.clear()
            self.source_disk_combo.addItems(source_options)
            
        elif op_type in ['RESTORE_IMAGE_TO_DISK', 'VERIFY_IMAGE']: 
            self.source_stacked_widget.setCurrentIndex(1) # Dosya Seçimi


        # --- HEDEF (Target) AYARLARI ---
        self.target_label.setText(lang.get('target_disk_file'))
        self.target_stacked_widget.setVisible(True)
        self.target_label.setVisible(True) 
        
        if op_type in ['BACKUP_CLONE', 'RESTORE_DISK_TO_DISK', 'RESTORE_IMAGE_TO_DISK', 'VERIFY_TWO_DISKS']:
            self.target_stacked_widget.setCurrentIndex(0) # Disk Combo
            target_options = [f"({lang.get('no_selection_made')})"]
            target_options.extend(self.AVAILABLE_DISKS)
            self.target_disk_combo.clear()
            self.target_disk_combo.addItems(target_options)

        elif op_type == 'BACKUP_IMAGE':
            self.target_stacked_widget.setCurrentIndex(1) # Dosya Kaydetme (Yeni İmaj)
            if self.target_path_edit_save:
                self.target_path_edit_save.setPlaceholderText(lang.get('create_image_placeholder'))
            
        elif op_type == 'VERIFY_IMAGE':
            self.target_stacked_widget.setCurrentIndex(2) # Dosya Açma (SHA512)
            self.target_label.setText(lang.get('sha512_verification_file'))
            if self.target_path_edit_open:
                self.target_path_edit_open.setPlaceholderText(lang.get('select_sha512_placeholder'))
            
        self.update_selection_variables()

    def update_details_page_visuals(self):
        MAX_WIDTH = WINDOW_WIDTH - IMAGE_WIDTH - 40 
        MAX_HEIGHT = 150 
        
        image_path = None
        
        # 1. Diskten Diske Klonlama/Kurtarma
        # Buradan 'VERIFY_TWO_DISKS' kaldırıldı
        if self.selected_operation_type in ['BACKUP_CLONE', 'RESTORE_DISK_TO_DISK']:
            image_path = "diskstatu.png" 
            self.source_text_label.setVisible(True)
            self.target_text_label.setVisible(True)
        
        # 2. İki Disk Karşılaştırması (Artık ayrı bir blokta)
        elif self.selected_operation_type == 'VERIFY_TWO_DISKS':
            image_path = "verifydisks.png" # İstenen doğru görsel
            self.source_text_label.setVisible(True)
            self.target_text_label.setVisible(True)
            
        # 3. Diskten İmaja Yedekleme
        elif self.selected_operation_type == 'BACKUP_IMAGE':
            image_path = "imgstatu.png" 
            self.source_text_label.setVisible(True)
            self.target_text_label.setVisible(True)
            
        # 4. İmajdan Diske Kurtarma
        elif self.selected_operation_type == 'RESTORE_IMAGE_TO_DISK':
            image_path = "imgstatu2.png" 
            self.source_text_label.setVisible(True)
            self.target_text_label.setVisible(True)
            
        # 5. İmaj Doğrulama
        elif self.selected_operation_type == 'VERIFY_IMAGE':
            image_path = "verifyimg.png"
            self.source_text_label.setVisible(True)
            self.target_text_label.setVisible(True)
            
        if image_path:
            full_path = resource_path("icons/" + image_path)
            pixmap = QPixmap(full_path)
            if not pixmap.isNull():
                scaled_pixmap = pixmap.scaled(MAX_WIDTH, MAX_HEIGHT, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                self.operation_image_label.setPixmap(scaled_pixmap)
            else:
                self.operation_image_label.setText("Görsel Yüklenemedi!")
                self.operation_image_label.setStyleSheet("color: red;")
        else:
            self.operation_image_label.clear()
        
        self.update_selection_variables()

    # Index 6: İşlem Başlıyor
    def create_step4_process_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        
        page.page_title_label = QLabel(lang.get('wizard_titles')[6])
        page.page_title_label.setFont(QFont("Sanserif", 12, QFont.Bold))
        layout.addWidget(page.page_title_label)
        
        description_text = QLabel(lang.get('operation_started_desc'))
        description_text.setWordWrap(True) 
        layout.addWidget(description_text)
        
        layout.addSpacing(15) 
        
        process_group = QGroupBox(lang.get('process_status')) 
        process_layout = QVBoxLayout(process_group)
        process_layout.setSpacing(10) 
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        process_layout.addWidget(self.progress_bar)
        
        self.output_text_edit = QTextEdit()
        self.output_text_edit.setReadOnly(True)
        self.output_text_edit.setFont(QFont("Monospace", 8))
        process_layout.addWidget(self.output_text_edit)
        
        layout.addWidget(process_group)
        layout.addStretch(1)
        return page

    def show_about_dialog(self):
        QMessageBox.about(self, lang.get('about_title'), lang.get('about_content'))


if __name__ == "__main__":
    if not os.path.exists("icons"):
        try:
            # Resimler için icons klasörünü oluştur
            os.makedirs("icons")
        except OSError:
            pass

######## White Rabbit###################
# One pill makes you larger
# And one pill makes you small
# And the ones that mother gives you
# Don't do anything at all
# Go ask Alice
# When she's ten feet tall
# And if you go chasing rabbits
# And you know you're going to fall
# Tell 'em a hookah-smoking caterpillar
# Has given you the call
# He called Alice
# When she was just small
# When the men on the chessboard
# Get up and tell you where to go
# And you've just had some kind of mushroom
# And your mind is moving low
# Go ask Alice
# I think she'll know
# When logic and proportion
# Have fallen sloppy dead
# And the White Knight is talking backwards
# And the Red Queen's off with her head
# Remember what the dormouse said
# Feed your head
# Feed your head
########### Jafferson Airplane ##########

    app = QApplication(sys.argv)
    window = SystemBackupWizard()
    window.show()
    sys.exit(app.exec_())
