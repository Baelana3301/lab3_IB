import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import hashlib
import os
import struct


# Реализация генератора Парка-Миллера из лабораторной работы №2
class ParkMillerGenerator:
    def __init__(self, seed=1):
        self.a = 16807  # γ5 = 16807
        self.m = 2 ** 31 - 1  # 2^31 - 1 = 2147483647
        self.state = seed

    def next_int(self):
        """Генерация следующего псевдослучайного числа"""
        self.state = (self.a * self.state) % self.m
        return self.state

    def next_bit(self):
        """Генерация следующего бита"""
        return self.next_int() % 2

    def next_bits(self, n):
        """Генерация последовательности из n битов"""
        return [self.next_bit() for _ in range(n)]

    def next_bytes(self, n):
        """Генерация n байтов"""
        bytes_list = []
        for _ in range(n):
            # Генерируем 4 байта из одного 32-битного числа
            num = self.next_int()
            bytes_list.extend(struct.pack('>I', num))
        return bytes(bytes_list[:n])


# Таблица подстановки из MaHash7
sTable = [
    0xa3, 0xd7, 0x09, 0x83, 0xf8, 0x48, 0xf6, 0xf4, 0xb3, 0x21, 0x15, 0x78, 0x99, 0xb1, 0xaf, 0xf9,
    0xe7, 0x2d, 0x4d, 0x8a, 0xce, 0x4c, 0xca, 0x2e, 0x52, 0x95, 0xd9, 0x1e, 0x4e, 0x38, 0x44, 0x28,
    0x0a, 0xdf, 0x02, 0xa0, 0x17, 0xf1, 0x60, 0x68, 0x12, 0xb7, 0x7a, 0xc3, 0xe9, 0xfa, 0x3d, 0x53,
    0x96, 0x84, 0x6b, 0xba, 0xf2, 0x63, 0x9a, 0x19, 0x7c, 0xae, 0xe5, 0xf5, 0xf7, 0x16, 0x6a, 0xa2,
    0x39, 0xb6, 0x7b, 0x0f, 0xc1, 0x93, 0x81, 0x1b, 0xee, 0xb4, 0x1a, 0xea, 0xd0, 0x91, 0x2f, 0xb8,
    0x55, 0xb9, 0xda, 0x85, 0x3f, 0x41, 0xbf, 0xe0, 0x5a, 0x58, 0x80, 0x5f, 0x66, 0x0b, 0xd8, 0x90,
    0x35, 0xd5, 0xc0, 0xa7, 0x33, 0x06, 0x65, 0x69, 0x45, 0x00, 0x94, 0x56, 0x6d, 0x98, 0x9b, 0x76,
    0x97, 0xfc, 0xb2, 0xc2, 0xb0, 0xfe, 0xdb, 0x20, 0xe1, 0xeb, 0xd6, 0xe4, 0xd4, 0x47, 0x4a, 0x1d,
    0x42, 0xed, 0x9e, 0x6e, 0x49, 0x3c, 0xcd, 0x43, 0x27, 0xd2, 0x07, 0xd4, 0xde, 0xc7, 0x67, 0x18,
    0x89, 0xcb, 0x30, 0x1f, 0x8d, 0xc6, 0x8f, 0xaa, 0xc8, 0x74, 0xdc, 0xc9, 0x5d, 0x5e, 0x31, 0xa4,
    0x70, 0x88, 0x61, 0x2c, 0x9f, 0x0d, 0x2b, 0x87, 0x50, 0x82, 0x54, 0x64, 0x26, 0x7d, 0x03, 0x40,
    0x34, 0x4b, 0x1c, 0x73, 0xd1, 0xc4, 0xfd, 0x3b, 0xcc, 0xfb, 0x7f, 0xab, 0xe6, 0x3e, 0x5b, 0xa5,
    0xad, 0x04, 0x23, 0x9c, 0x14, 0x51, 0x22, 0xf0, 0x29, 0x79, 0x71, 0x7e, 0xff, 0x8c, 0x0e, 0xe2,
    0x0c, 0xef, 0xbc, 0x72, 0x75, 0x6f, 0x37, 0xa1, 0xec, 0xd3, 0x8e, 0x62, 0x8b, 0x86, 0x10, 0xe8,
    0x08, 0x77, 0x11, 0xbe, 0x92, 0x4f, 0x24, 0xc5, 0x32, 0x36, 0x9d, 0xcf, 0xf3, 0xa6, 0xbb, 0xac,
    0x5e, 0x6c, 0xa9, 0x13, 0x57, 0x25, 0xb5, 0xe3, 0xbd, 0xa8, 0x3a, 0x01, 0x05, 0x59, 0x2a, 0x46
]


# Реализация MaHash8
def LROT14(x):
    """Циклический сдвиг влево на 14 бит"""
    return ((x << 14) | (x >> 18)) & 0xFFFFFFFF


def RROT14(x):
    """Циклический сдвиг вправо на 14 бит"""
    return ((x << 18) | (x >> 14)) & 0xFFFFFFFF


def MaHash8(data):
    """Реализация хеш-функции MaHash8"""
    if isinstance(data, str):
        data = data.encode('utf-8')

    length = len(data)
    hash1 = length
    hash2 = length

    for i in range(length):
        byte_val = data[i]
        index = (byte_val + i) & 0xFF

        # Обновление hash1
        hash1 += sTable[index]
        hash1 = LROT14(hash1 + ((hash1 << 6) ^ (hash1 >> 11))) & 0xFFFFFFFF

        # Обновление hash2
        hash2 += sTable[index]
        hash2 = RROT14(hash2 + ((hash2 << 6) ^ (hash2 >> 11))) & 0xFFFFFFFF

        # Перестановка частей хешей
        sh1 = hash1
        sh2 = hash2
        hash1 = ((sh1 >> 16) & 0xFFFF) | ((sh2 & 0xFFFF) << 16)
        hash2 = ((sh2 >> 16) & 0xFFFF) | ((sh1 & 0xFFFF) << 16)

    return hash1 ^ hash2


def ma_hash8_hex(data):
    """MaHash8 в шестнадцатеричном формате"""
    return format(MaHash8(data), '08x')


# Готовая хеш-функция (MD5)
def ready_hash(data):
    """Использование готовой хеш-функции MD5"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.md5(data).hexdigest()


class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Потоковое шифрование и хеширование - Вариант 4")
        self.root.geometry("800x700")

        # Генератор для шифрования
        self.generator = ParkMillerGenerator()

        # Переменные
        self.current_file = None
        self.encrypted_data = None

        self.create_widgets()

    def create_widgets(self):
        """Создание элементов интерфейса"""
        # Заголовок
        title_label = tk.Label(self.root, text="Потоковое шифрование и хеширование",
                               font=("Arial", 14, "bold"))
        title_label.pack(pady=10)

        # Создание вкладок
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)

        # Вкладка хеширования
        hash_frame = ttk.Frame(notebook)
        notebook.add(hash_frame, text="Хеширование паролей")

        # Вкладка шифрования
        crypto_frame = ttk.Frame(notebook)
        notebook.add(crypto_frame, text="Шифрование/Дешифрование")

        self.setup_hash_tab(hash_frame)
        self.setup_crypto_tab(crypto_frame)

        # Статус бар
        self.status_var = tk.StringVar()
        self.status_var.set("Готов к работе")
        status_bar = tk.Label(self.root, textvariable=self.status_var, bd=1,
                              relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def setup_hash_tab(self, parent):
        """Настройка вкладки хеширования"""
        # Пароль
        tk.Label(parent, text="Пароль:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.password_entry = tk.Entry(parent, width=50, show="*")
        self.password_entry.grid(row=0, column=1, padx=5, pady=5, sticky='ew')

        # Кнопки хеширования
        hash_buttons_frame = tk.Frame(parent)
        hash_buttons_frame.grid(row=1, column=0, columnspan=2, pady=10)

        self.btn_hash_md5 = tk.Button(hash_buttons_frame, text="Хеш (MD5)",
                                      command=self.hash_md5, padx=10, pady=5, bg="lightblue")
        self.btn_hash_md5.pack(side=tk.LEFT, padx=5)

        self.btn_hash_mahash8 = tk.Button(hash_buttons_frame, text="Хеш (MaHash8)",
                                          command=self.hash_mahash8, padx=10, pady=5, bg="lightgreen")
        self.btn_hash_mahash8.pack(side=tk.LEFT, padx=5)

        self.btn_hash_both = tk.Button(hash_buttons_frame, text="Оба хеша",
                                       command=self.hash_both, padx=10, pady=5, bg="orange")
        self.btn_hash_both.pack(side=tk.LEFT, padx=5)

        # Результаты хеширования
        tk.Label(parent, text="Результаты хеширования:").grid(row=2, column=0, padx=5, pady=5, sticky='w')

        self.hash_results_text = scrolledtext.ScrolledText(parent, width=70, height=8)
        self.hash_results_text.grid(row=3, column=0, columnspan=2, padx=5, pady=5, sticky='nsew')

        parent.columnconfigure(1, weight=1)
        parent.rowconfigure(3, weight=1)

    def setup_crypto_tab(self, parent):
        """Настройка вкладки шифрования"""
        # Пароль для шифрования
        tk.Label(parent, text="Пароль для шифрования:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.crypto_password_entry = tk.Entry(parent, width=50, show="*")
        self.crypto_password_entry.grid(row=0, column=1, padx=5, pady=5, sticky='ew')

        # Файловые операции
        file_buttons_frame = tk.Frame(parent)
        file_buttons_frame.grid(row=1, column=0, columnspan=2, pady=10)

        self.btn_select_file = tk.Button(file_buttons_frame, text="Выбрать файл",
                                         command=self.select_file, padx=10, pady=5, bg="lightyellow")
        self.btn_select_file.pack(side=tk.LEFT, padx=5)

        self.btn_encrypt = tk.Button(file_buttons_frame, text="Зашифровать",
                                     command=self.encrypt_file, padx=10, pady=5, bg="lightgreen")
        self.btn_encrypt.pack(side=tk.LEFT, padx=5)

        self.btn_decrypt = tk.Button(file_buttons_frame, text="Расшифровать",
                                     command=self.decrypt_file, padx=10, pady=5, bg="lightcoral")
        self.btn_decrypt.pack(side=tk.LEFT, padx=5)

        self.btn_save_result = tk.Button(file_buttons_frame, text="Сохранить результат",
                                         command=self.save_result, padx=10, pady=5, bg="lightblue")
        self.btn_save_result.pack(side=tk.LEFT, padx=5)

        # Информация о файле
        tk.Label(parent, text="Информация о файле:").grid(row=2, column=0, padx=5, pady=5, sticky='w')
        self.file_info_text = scrolledtext.ScrolledText(parent, width=70, height=10)
        self.file_info_text.grid(row=3, column=0, columnspan=2, padx=5, pady=5, sticky='nsew')

        # Прогресс бар
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(parent, variable=self.progress_var, maximum=100)
        self.progress_bar.grid(row=4, column=0, columnspan=2, padx=5, pady=5, sticky='ew')

        parent.columnconfigure(1, weight=1)
        parent.rowconfigure(3, weight=1)

    def hash_md5(self):
        """Хеширование с помощью MD5"""
        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("Предупреждение", "Введите пароль")
            return

        hash_result = ready_hash(password)

        self.hash_results_text.delete(1.0, tk.END)
        self.hash_results_text.insert(tk.END, f"Пароль: {password}\n")
        self.hash_results_text.insert(tk.END, f"MD5 хеш: {hash_result}\n")
        self.hash_results_text.insert(tk.END, f"Длина: {len(hash_result)} символов\n")

        self.status_var.set("MD5 хеш вычислен")

    def hash_mahash8(self):
        """Хеширование с помощью MaHash8"""
        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("Предупреждение", "Введите пароль")
            return

        hash_result = ma_hash8_hex(password)

        self.hash_results_text.delete(1.0, tk.END)
        self.hash_results_text.insert(tk.END, f"Пароль: {password}\n")
        self.hash_results_text.insert(tk.END, f"MaHash8 хеш: {hash_result}\n")
        self.hash_results_text.insert(tk.END, f"Длина: {len(hash_result)} символов\n")

        self.status_var.set("MaHash8 хеш вычислен")

    def hash_both(self):
        """Хеширование обоими методами"""
        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("Предупреждение", "Введите пароль")
            return

        md5_hash = ready_hash(password)
        mahash8_hash = ma_hash8_hex(password)

        self.hash_results_text.delete(1.0, tk.END)
        self.hash_results_text.insert(tk.END, f"Пароль: {password}\n\n")
        self.hash_results_text.insert(tk.END, f"MD5 хеш: {md5_hash}\n")
        self.hash_results_text.insert(tk.END, f"Длина: {len(md5_hash)} символов\n\n")
        self.hash_results_text.insert(tk.END, f"MaHash8 хеш: {mahash8_hash}\n")
        self.hash_results_text.insert(tk.END, f"Длина: {len(mahash8_hash)} символов\n")

        self.status_var.set("Оба хеша вычислены")

    def select_file(self):
        """Выбор файла для шифрования/дешифрования"""
        filename = filedialog.askopenfilename()
        if filename:
            self.current_file = filename
            file_size = os.path.getsize(filename)

            self.file_info_text.delete(1.0, tk.END)
            self.file_info_text.insert(tk.END, f"Выбран файл: {filename}\n")
            self.file_info_text.insert(tk.END, f"Размер: {file_size} байт\n")
            self.file_info_text.insert(tk.END, f"Тип: {'Текстовый' if file_size < 1024 else 'Бинарный'}\n")

            # Показ превью для текстовых файлов
            if file_size < 1024:  # Показываем превью только для маленьких файлов
                try:
                    with open(filename, 'r', encoding='utf-8') as f:
                        preview = f.read(200)
                        self.file_info_text.insert(tk.END, f"\nПревью:\n{preview}")
                        if file_size > 200:
                            self.file_info_text.insert(tk.END, "\n... (файл обрезан)")
                except:
                    self.file_info_text.insert(tk.END, "\n(не удалось прочитать как текст)")

            self.status_var.set(f"Выбран файл: {os.path.basename(filename)}")

    def init_generator_from_password(self, password):
        """Инициализация генератора из пароля"""
        seed = MaHash8(password)  # Используем MaHash8 для создания seed из пароля
        self.generator = ParkMillerGenerator(seed)

    def encrypt_file(self):
        """Шифрование файла"""
        if not self.current_file:
            messagebox.showwarning("Предупреждение", "Сначала выберите файл")
            return

        password = self.crypto_password_entry.get()
        if not password:
            messagebox.showwarning("Предупреждение", "Введите пароль для шифрования")
            return

        try:
            self.status_var.set("Шифрование...")
            self.progress_var.set(0)
            self.root.update()

            # Инициализация генератора из пароля
            self.init_generator_from_password(password)

            # Чтение файла
            with open(self.current_file, 'rb') as f:
                file_data = f.read()

            # Генерация ключевого потока
            key_stream = self.generator.next_bytes(len(file_data))

            # Шифрование XOR
            encrypted = bytes([file_data[i] ^ key_stream[i] for i in range(len(file_data))])

            self.encrypted_data = encrypted

            self.file_info_text.delete(1.0, tk.END)
            self.file_info_text.insert(tk.END, f"Файл зашифрован: {self.current_file}\n")
            self.file_info_text.insert(tk.END, f"Исходный размер: {len(file_data)} байт\n")
            self.file_info_text.insert(tk.END, f"Зашифрованный размер: {len(encrypted)} байт\n")
            self.file_info_text.insert(tk.END, f"Пароль: {password}\n")
            self.file_info_text.insert(tk.END, f"Seed (из хеша пароля): {MaHash8(password)}\n")

            self.progress_var.set(100)
            self.status_var.set("Файл зашифрован")

        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при шифровании: {str(e)}")
            self.status_var.set("Ошибка шифрования")

    def decrypt_file(self):
        """Дешифрование файла"""
        if not self.current_file:
            messagebox.showwarning("Предупреждение", "Сначала выберите файл")
            return

        password = self.crypto_password_entry.get()
        if not password:
            messagebox.showwarning("Предупреждение", "Введите пароль для дешифрования")
            return

        try:
            self.status_var.set("Дешифрование...")
            self.progress_var.set(0)
            self.root.update()

            # Инициализация генератора из пароля
            self.init_generator_from_password(password)

            # Чтение зашифрованного файла
            with open(self.current_file, 'rb') as f:
                encrypted_data = f.read()

            # Генерация ключевого потока
            key_stream = self.generator.next_bytes(len(encrypted_data))

            # Дешифрование XOR
            decrypted = bytes([encrypted_data[i] ^ key_stream[i] for i in range(len(encrypted_data))])

            self.encrypted_data = decrypted

            self.file_info_text.delete(1.0, tk.END)
            self.file_info_text.insert(tk.END, f"Файл расшифрован: {self.current_file}\n")
            self.file_info_text.insert(tk.END, f"Размер данных: {len(decrypted)} байт\n")
            self.file_info_text.insert(tk.END, f"Пароль: {password}\n")

            # Попытка показать превью для текста
            try:
                text_preview = decrypted[:200].decode('utf-8')
                self.file_info_text.insert(tk.END, f"\nПревью:\n{text_preview}")
                if len(decrypted) > 200:
                    self.file_info_text.insert(tk.END, "\n... (данные обрезаны)")
            except:
                self.file_info_text.insert(tk.END, "\n(бинарные данные)")

            self.progress_var.set(100)
            self.status_var.set("Файл расшифрован")

        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при дешифровании: {str(e)}")
            self.status_var.set("Ошибка дешифрования")

    def save_result(self):
        """Сохранение результата шифрования/дешифрования"""
        if self.encrypted_data is None:
            messagebox.showwarning("Предупреждение", "Нет данных для сохранения")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".bin",
            filetypes=[("All files", "*.*"), ("Text files", "*.txt"), ("Binary files", "*.bin")]
        )

        if filename:
            try:
                with open(filename, 'wb') as f:
                    f.write(self.encrypted_data)

                messagebox.showinfo("Успех", f"Данные сохранены в файл:\n{filename}")
                self.status_var.set(f"Данные сохранены: {os.path.basename(filename)}")

            except Exception as e:
                messagebox.showerror("Ошибка", f"Ошибка при сохранении: {str(e)}")
                self.status_var.set("Ошибка сохранения")


def main():
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()