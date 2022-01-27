#   Модуль/и для шифрования/дешифровки текста методом AES-128-CBC
# (можно использовать библиотеку cryptography).
#   Передаем файл с текстом на вход приложению и директорию вывода зашифрованного файла.
#   Приложение подключается к БД (Установить локально PostgreSQL) и забирает оттуда вектор
# инициализации и ключ шифрования (которые мы заранее подготовили и сохранили в таблице),
# шифрует текст и сохраняет в текстовом файле в переданной директории. 
# Для дешифровки подаем файл и директорию вывода на вход приложению, оно подключается к БД,
# забирает все нужное и сохраняет дешифрованный текст в файле в переданной директории.
#   Код должен быть написан в соответствии со стандартами PEP8 +
# использовать линтер для проверки (pylint свежей версии).

from hashlib import algorithms_available
from socket import NI_NAMEREQD
import tkinter as tk
import tkinter.messagebox as mb
import tkinter.filedialog as fd

# Во время разбора библиотеки cryptography было выявлено, что она использует библиотеку Crypto
# Поэтому было принято решение сразу использовать Crypto.Cipher
# from cryptography.fernet import Fernet

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii

# Библиотеки для подключения к БД
import psycopg2
from psycopg2 import Error


class App(tk.Tk):

    def __init__(self):
        super().__init__()
        
        self.file = None
        self.text = None
        self.directory = None
        self.labelFile = None
        self.labelDirectory = None

        self.key = None
        self.IV = None
        self.message = None
        self.cipherText = None

        self.engine()

        self.key = pad(bytes(self.key, encoding='utf-8'), AES.block_size)
        self.IV = pad(bytes(self.IV, encoding='utf-8'), AES.block_size)

        self.set_default()


    # Метод создания объектов в окне
    def set_default(self):
        self.btn_crypt = tk.Button(self, text="Шифрование",
                                    command=self.crypt)
        self.btn_decrypt = tk.Button(self, text="Дешифрование",
                                    command=self.decrypt)              
        self.btn_file = tk.Button(self, text="Выберите файл",
                                    command=self.choose_file)
        self.btn_directory = tk.Button(self, text="Выберите директорию",
                                    command=self.choose_directory)
        self.labelFile = tk.Label(self, text = self.file)
        self.labelDirectory = tk.Label(self, text = self.directory)

        self.opts = {'padx': 40, 'pady': 5, 'expand': True, 'fill': tk.BOTH}

        self.btn_file.pack(**self.opts)
        self.labelFile.pack()
        self.btn_directory.pack(**self.opts)
        self.labelDirectory.pack()
        self.btn_crypt.pack(**self.opts)
        self.btn_decrypt.pack(**self.opts)
        

    # Метод выбора файла
    def choose_file(self):
        filetypes = (("Текстовый файл", "*.txt"),
                    ("Любой", "*"))
        self.file = fd.askopenfilename(title="Открыть файл", initialdir="/",
                                      filetypes=filetypes)
        if self.file:
            print("file: ", self.file)
            self.labelFile.config(text = self.file)
            self.labelFile.pack()
        
        with open(self.file) as fcur_obj:
            self.text = fcur_obj.read()


    # Метод выбора директории
    def choose_directory(self):
        self.directory = fd.askdirectory(title="Открыть папку", initialdir="/")
        if self.directory:
            print("dir:", self.directory)
            self.labelDirectory.config(text = self.directory)
            self.labelDirectory.pack()


    # Метод шифрования
    def crypt(self):
        
        if not self.text:
            mb.showerror("Ошибка", "Выберите файл с текстом!")
            return
        if not self.directory:
            mb.showerror("Ошибка", "Выберите директорию")
            return

        self.message = self.text
        dataBytes = bytes(self.message, 'utf-8')
        padded_bytes = pad(dataBytes, AES.block_size)
        AES_obj = AES.new(self.key, AES.MODE_CBC, self.IV)
        self.cipherText = AES_obj.encrypt(padded_bytes)

        self.cipherText = binascii.hexlify(self.cipherText).decode()

        msg = f"Шифрование выполнено!\nТекст:\n{self.message}\
                \nШифр:\n{self.cipherText}"
        mb.showinfo("Информация", msg)

        with open(self.directory + '/CipherGenerated.txt', mode='w') as fcur_obj:
            fcur_obj.write(self.cipherText)


    # Метод Дешифровки
    def decrypt(self):

        if not self.text:
            mb.showerror("Ошибка", "Выберите файл с текстом!")
            return
        if not self.directory:
            mb.showerror("Ошибка", "Выберите директорию")
            return

        self.cipherText = binascii.unhexlify(self.text)
        AES_obj = AES.new(self.key, AES.MODE_CBC, self.IV)
        raw_bytes = AES_obj.decrypt(self.cipherText)
        self.message = unpad(raw_bytes, AES.block_size).decode()

        msg = f"Дешифрование выполнено!\nТекст:\n{self.message}\
                \nШифр:\n{self.text}"
        mb.showinfo("Информация", msg)

        with open(self.directory + '/MessageGenerated.txt', mode='w') as fcur_obj:
            fcur_obj.write(self.message)


    # Метод подключения к БД и получения данных
    def engine(self):
        try:
            # Подключение к базе данных
            connection = psycopg2.connect(user="postgres",
                                        password="marrik98",
                                        database="GlowByte",
                                        host="127.0.0.1",
                                        port="5432")
            # Курсор для выполнения операций с базой данных
            cursor = connection.cursor()
            # Выполнение SQL-запроса
            cursor.execute("SELECT key, iv\
                            FROM aes128cbc\
                            limit 1")
            # Получить результат
            record = cursor.fetchone()
            print(record)
            self.key = record[0]
            self.IV = record[1]
        except (Exception, Error) as error:
            print("Ошибка при работе с PostgreSQL", error)
        finally:
            if connection:
                cursor.close()
                connection.close()
                print("Соединение с PostgreSQL закрыто")
        

if __name__ == "__main__":
    app = App()
    app.mainloop()