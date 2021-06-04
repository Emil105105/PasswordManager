#!/usr/bin/env python3
# FileEncryption.py, Copyright(c) 2021 Martin S. Merkli
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.


import hashlib
import tkinter as tk
from tkinter import messagebox
from ast import literal_eval
import sys
import os
import time
import random


def hash_password(password: str) -> bytes:
    try:
        with open('config.txt', 'r') as config_file:
            salt = literal_eval(config_file.readlines()[1])
        key = hashlib.pbkdf2_hmac('sha512', password.encode(), salt, 100000)
        return key
    except FileNotFoundError:
        recover()


def xor(x: bytes, y: bytes) -> bytes:
    return bytes([_a ^ _b for _a, _b in zip(x, y)])


def encrypt(text: str, password: str) -> bytes:
    key = hash_password(password)
    data = text.encode()
    while len(key) < len(data):
        key += key
    cipher = xor(data, key)
    return cipher


def decrypt(cipher: bytes, password: str) -> str:
    key = hash_password(password)
    while len(key) < len(cipher):
        key += key
    data = xor(cipher, key)
    text = data.decode()
    return text


def copy(text: str, window: tk.Tk) -> None:
    window.clipboard_clear()
    window.clipboard_append(text)
    window.update()


def raise_error(error: str, code: int, modes: list) -> None:
    if 'messagebox' in modes:
        messagebox.showerror('Error ' + str(code) + ' - PasswordManager', error + '\nCode: ' + str(code))
    if 'quit' in modes:
        sys.exit()


def translate_init() -> None:
    global _language
    supported_languages = ['EN', 'DE']
    for supported_language in supported_languages:
        try:
            with open(supported_language + '.txt', 'r') as language_file:
                _language = []
                for line in language_file.readlines():
                    _language.append(line.replace('\n', ''))
                return None
        except FileNotFoundError:
            pass
    raise_error('no language installed', 102, ['messagebox', 'quit'])


def translate(index: int) -> str:
    global _language
    return _language[index - 1]


def recover() -> None:
    messagebox.showwarning(translate(50) + ' - ' + translate(1), translate(51) + '\n' + translate(52))


def get_names(password: str) -> list:
    try:
        with open('passwords.bin', 'rb') as encrypted_password_file:
            informations = literal_eval(decrypt(encrypted_password_file.read(), password))
            names = []
            for information in informations:
                names.append(information[0])
            return names
    except FileNotFoundError:
        recover()


def get_informations(password: str) -> list:
    try:
        with open('passwords.bin', 'rb') as encrypted_password_file:
            informations = literal_eval(decrypt(encrypted_password_file.read(), password))
            return informations
    except FileNotFoundError:
        recover()


def get_information(name: str, password: str) -> list:
    try:
        with open('passwords.bin', 'rb') as encrypted_password_file:
            informations = literal_eval(decrypt(encrypted_password_file.read(), password))
            for information in informations:
                if information[0] == name:
                    return information
            raise_error('an unknown error accrued', 102, ['messagebox', 'quit'])
    except FileNotFoundError:
        recover()


def get_descriptions(password: str) -> list:
    try:
        with open('passwords.bin', 'rb') as encrypted_password_file:
            informations = literal_eval(decrypt(encrypted_password_file.read(), password))
            descriptions = []
            for information in informations:
                descriptions.append(information[1])
            return descriptions
    except FileNotFoundError:
        recover()


def get_string_time() -> str:
    return time.asctime().split(' ')[4]


def generate_password_dialog(information_name) -> None:
    global _password
    window = tk.Tk()
    window.title(translate(39) + ' - ' + translate(1))
    a = tk.Label(window, text=translate(40))
    b = tk.Entry(window, width=16)
    c_pressed = tk.BooleanVar()
    c_pressed.set(False)
    c = tk.Button(window, text=translate(25), command=lambda: c_pressed.set(True))
    a.grid(row=0, column=0)
    b.grid(row=1, column=0)
    c.grid(row=2, column=0)
    b.insert(0, '16')
    loop = True
    length = 16
    while loop:
        try:
            window.update()
            if b.get().isdigit():
                c.config(state=tk.NORMAL)
            else:
                c.config(state=tk.DISABLED)
                c_pressed.set(False)
            if c_pressed.get():
                length = int(b.get())
                window.destroy()
        except tk.TclError:
            return None
    password = generate_password(length)
    informations = get_informations(_password)
    names = []
    for information in informations:
        names.append(information[0])
    informations[names.index(information_name)][3] = password
    change_information(informations)


def generate_password(length: int = 16) -> str:
    characters = ['q', 'w', 'e', 'r', 't', 'z', 'u', 'i', 'o', 'p', 'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', 'y',
                  'x', 'c', 'v', 'b', 'n', 'm', 'Q', 'W', 'E', 'R', 'T', 'Z', 'U', 'I', 'O', 'P', 'A', 'S', 'D', 'F',
                  'G', 'H', 'J', 'K', 'L', 'Y', 'X', 'C', 'V', 'B', 'N', 'M', '1', '2', '3', '4', '5', '6', '7', '8',
                  '9', '0', ',', '.', '-', ';', ':', '_', '+', '=', ')', '(', '%', '&', '/', '@', '{', '}', '$', '[',
                  ']', '?', '!', '<', '>']
    password = ''
    for i in range(length):
        password += random.choice(characters)
    return password


def is_secure_password(password: str) -> bool:
    score = 0
    if len(password) >= 4:
        score += 1
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    if len(password) >= 16:
        score += 1
    if len(password) >= 64:
        score += 8
    for i in ['q', 'w', 'e', 'r', 't', 'z', 'u', 'i', 'o', 'p', 'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', 'y', 'x',
              'c', 'v', 'b', 'n', 'm']:
        if i in password:
            score += 1
            break
    for i in ['Q', 'W', 'E', 'R', 'T', 'Z', 'U', 'I', 'O', 'P', 'A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L', 'Y', 'X',
              'C', 'V', 'B', 'N', 'M']:
        if i in password:
            score += 1
            break
    for i in ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0']:
        if i in password:
            score += 1
            break
    for i in [',', '.', '-', ';', ':', '_', '+', '=', ')', '(', '%', '&', '/', '@', '{', '}', '$', '[', ']', '?', '!',
              '<', '>']:
        if i in password:
            score += 1
            break
    password2 = password
    for i in ['q', 'w', 'e', 'r', 't', 'z', 'u', 'i', 'o', 'p', 'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', 'y', 'x',
              'c', 'v', 'b', 'n', 'm', 'Q', 'W', 'E', 'R', 'T', 'Z', 'U', 'I', 'O', 'P', 'A', 'S', 'D', 'F', 'G', 'H',
              'J', 'K', 'L', 'Y', 'X', 'C', 'V', 'B', 'N', 'M', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', ',',
              '.', '-', ';', ':', '_', '+', '=', ')', '(', '%', '&', '/', '@', '{', '}', '$', '[', ']', '?', '!', '<',
              '>']:
        password2.replace(i, '')
    if len(password2) > 0:
        score += 1
    if score >= 6:
        return True
    else:
        return False


def setup() -> str:
    with open('config.txt', 'w') as config_file:
        setup_window = tk.Tk()
        setup_window.title(translate(19) + '! - ' + translate(1))
        a = tk.Label(setup_window, text=translate(20))
        b = tk.Entry(setup_window, show='*', width=32)
        c = tk.Label(setup_window, text='')
        d = tk.Label(setup_window, text=translate(23))
        e = tk.Entry(setup_window, show='*', width=32)
        f = tk.Label(setup_window, text='')
        g = tk.Button(setup_window, text=translate(25), width=32, command=lambda: loop.set(False))
        a.grid(row=0, column=0)
        b.grid(row=1, column=0)
        c.grid(row=2, column=0)
        d.grid(row=3, column=0)
        e.grid(row=4, column=0)
        f.grid(row=5, column=0)
        g.grid(row=6, column=0)
        loop = tk.BooleanVar()
        loop.set(True)
        while loop.get():
            if b.get() == '' or ' ' in b.get():
                g.config(state=tk.DISABLED)
                c.config(text=translate(24))
                f.config(text='')
            elif not is_secure_password(b.get()):
                g.config(state=tk.DISABLED)
                c.config(text=translate(22))
                f.config(text='')
            elif b.get() != e.get():
                g.config(state=tk.DISABLED)
                c.config(text=translate(21))
                f.config(text=translate(26))
            else:
                g.config(state=tk.NORMAL)
                c.config(text=translate(21))
                f.config(text='')
            setup_window.update()
        password = b.get()
        example = [[translate(27), 'example.com', 'user1234', generate_password(16)]]
        salt = os.urandom(32)
        config_file.write(str(hashlib.pbkdf2_hmac('sha512', password.encode(), salt, 128000)) + '\n')
        config_file.write(str(salt) + '\n')
        config_file.write(str(int(time.time())) + '\n')
    with open('passwords.bin', 'wb') as passwords_file:
        passwords_file.write(encrypt(str(example), password))
    return password


def backup_message() -> None:
    with open('config.txt', 'r') as config_file:
        config = config_file.readlines()
        last_backup = int(config[2])
        if last_backup == 0:
            return None
        elif int(time.time()) - last_backup >= 1000000:
            messagebox.showwarning(translate(31) + ' - ' + translate(1), translate(32))
            config[2] = str(int(time.time()))
        else:
            return None
    with open('config.txt', 'w') as config_file:
        config_file.writelines(config)


def change_information(new_information: list) -> None:
    global _password
    with open('passwords.bin', 'wb') as password_file:
        cipher = encrypt(str(new_information), _password)
        password_file.write(cipher)


def add_information_dialog() -> None:
    global _password
    add_window = tk.Tk()
    add_window.title(translate(16) + ' - ' + translate(1))
    a1 = tk.Label(add_window, text=translate(4) + ':', width=16)
    a2 = tk.Entry(add_window, width=32)
    b1 = tk.Label(add_window, text=translate(5) + '/' + translate(6) + ':', width=16)
    b2 = tk.Entry(add_window, width=32)
    c1 = tk.Label(add_window, text=translate(7) + ':', width=16)
    c2 = tk.Entry(add_window, width=32)
    d1 = tk.Label(add_window, text=translate(8) + ':', width=16)
    d2 = tk.Entry(add_window, width=32)
    e2_pressed = tk.BooleanVar()
    e2_pressed.set(False)
    e2 = tk.Button(add_window, text=translate(12), command=lambda: e2_pressed.set(True), width=32)
    f = tk.Label(add_window, text='')
    g_pressed = tk.BooleanVar()
    g_pressed.set(False)
    g = tk.Button(add_window, text=translate(16), command=lambda: g_pressed.set(True), width=50)
    a1.grid(row=0, column=0)
    a2.grid(row=0, column=1)
    b1.grid(row=1, column=0)
    b2.grid(row=1, column=1)
    c1.grid(row=2, column=0)
    c2.grid(row=2, column=1)
    d1.grid(row=3, column=0)
    d2.grid(row=3, column=1)
    e2.grid(row=4, column=1)
    f.grid(row=5, column=0, columnspan=2)
    g.grid(row=6, column=0, columnspan=2)
    loop = tk.BooleanVar()
    loop.set(True)
    while loop.get():
        try:
            if a2.get() == '' or b2.get() == '' or c2.get() == '' or d2.get() == '' or a2.get() in get_names(_password):
                g.config(state=tk.DISABLED)
                f.config(text=translate(45))
            else:
                g.config(state=tk.NORMAL)
                f.config(text='')
            if e2_pressed.get():
                e2_pressed.set(False)
                generate_window = tk.Tk()
                generate_window.title(translate(12) + ' - ' + translate(1))
                x = tk.Label(generate_window, text=translate(40))
                y = tk.Entry(generate_window, width=16)
                z_pressed = tk.BooleanVar()
                z_pressed.set(False)
                z = tk.Button(generate_window, text=translate(25), width=16, command=lambda: z_pressed.set(True))
                x.grid(row=0, column=0)
                y.grid(row=1, column=0)
                z.grid(row=2, column=0)
                loop2 = tk.BooleanVar()
                loop2.set(True)
                while loop2.get():
                    try:
                        try:
                            int(y.get())
                            z.config(state=tk.NORMAL)
                        except (ValueError, TypeError):
                            z.config(state=tk.DISABLED)
                        generate_window.update()
                        if z_pressed.get():
                            try:
                                y_int = int(y.get())
                                d2.delete(0, len(d2.get()) + 1)
                                d2.insert(0, generate_password(y_int))
                                loop2.set(False)
                                generate_window.destroy()
                            except (ValueError, TypeError):
                                pass
                    except tk.TclError:
                        loop2.set(False)
            add_window.update()
            if g_pressed.get():
                loop.set(False)
                g_pressed.set(False)
                new_password = [a2.get(), b2.get(), c2.get(), d2.get()]
                add_information(new_password)
                add_window.destroy()
        except tk.TclError:
            loop.set(False)


def add_information(information: list) -> None:
    global _password
    old = get_informations(_password)
    old.append(information)
    change_information(old)


def settings_menu() -> None:
    global _password
    settings_window = tk.Tk()
    settings_window.title(translate(14) + ' - ' + translate(1))
    with open('config.txt', 'r') as config_file:
        config = config_file.readlines()
    a_selected = tk.BooleanVar()
    a_selected_old = tk.BooleanVar()
    a = tk.Checkbutton(settings_window, text=translate(43), variable=a_selected, onvalue=True, offvalue=False)
    b = tk.Button(settings_window, text=translate(44), command=change_password, width=32)
    a.grid(row=0, column=0)
    b.grid(row=1, column=0)
    if int(config[2]) != 0:
        a_selected.set(True)
        a.select()
        a_selected_old.set(True)
    else:
        a_selected.set(False)
        a.deselect()
        a_selected_old.set(False)
    loop = tk.BooleanVar()
    loop.set(True)
    while loop.get():
        try:
            settings_window.update()
            if a_selected.get() != a_selected_old.get():
                a_selected_old.set(a_selected.get())
                if a_selected.get():
                    config[2] = str(int(time.time()))
                else:
                    config[2] = str(0)
                with open('config.txt', 'w') as config_file:
                    config_file.writelines(config)
        except tk.TclError:
            loop.set(False)


def change_password() -> None:
    global _password
    if messagebox.askyesnocancel(translate(44) + ' - ' + translate(1), translate(36) + '\n' + translate(38)):
        old_password = _password
        informations = get_informations(_password)
        change_window = tk.Tk()
        change_window.title(translate(44) + ' - ' + translate(1))
        a1 = tk.Label(change_window, text=translate(46), width=32)
        a2 = tk.Entry(change_window, width=32)
        b1 = tk.Label(change_window, text=translate(47), width=32)
        b2 = tk.Entry(change_window, width=32)
        c1 = tk.Label(change_window, text=translate(48), width=32)
        c2 = tk.Entry(change_window, width=32)
        d = tk.Label(change_window, text='')
        e1_pressed = tk.BooleanVar()
        e1_pressed.set(False)
        e1 = tk.Button(change_window, text=translate(49), command=lambda: e1_pressed.set(True), width=32)
        e2_pressed = tk.BooleanVar()
        e2_pressed.set(False)
        e2 = tk.Button(change_window, text=translate(25), command=lambda: e1_pressed.set(True), width=32)
        a1.grid(row=0, column=0)
        a2.grid(row=0, column=1)
        b1.grid(row=1, column=0)
        b2.grid(row=1, column=1)
        c1.grid(row=2, column=0)
        c2.grid(row=2, column=1)
        d.grid(row=3, column=0, columnspan=2)
        e1.grid(row=4, column=0)
        e2.grid(row=4, column=1)
        loop = tk.BooleanVar()
        loop.set(True)
        while loop.get():
            try:
                if a2.get() != old_password or ' ' in b2.get() or b2.get() != c2.get() or \
                        not is_secure_password(b2.get()):
                    e2.config(state=tk.DISABLED)
                    d.config(text=translate(45))
                else:
                    e2.config(state=tk.NORMAL)
                    d.config(text='')
                change_window.update()
                if e1_pressed.get():
                    e1_pressed.set(False)
                    loop.set(False)
                    change_window.destroy()
                    return None
                if e2_pressed.get():
                    e1_pressed.set(False)
                    loop.set(False)
                    change_window.destroy()
                    _password = b2.get()
                    with open('passwords.bin', 'wb') as password_file:
                        cipher = encrypt(str(informations), _password)
                        password_file.write(cipher)
            except tk.TclError:
                loop.set(False)
    else:
        return None


def open_about() -> None:
    messagebox.showinfo(translate(15) + ' - ' + translate(1), translate(17) + '\n' + translate(18))


def forgot_password() -> None:
    messagebox.showinfo(translate(41) + ' - ' + translate(1), translate(42))


def edit_dialog(name: str) -> None:
    global _password
    edit_window = tk.Tk()
    edit_window.title(translate(13) + ' - ' + translate(1))
    a1 = tk.Label(edit_window, text=translate(4) + ':', width=16)
    a2 = tk.Entry(edit_window, width=32)
    b1 = tk.Label(edit_window, text=translate(5) + '/' + translate(6) + ':', width=16)
    b2 = tk.Entry(edit_window, width=32)
    c1 = tk.Label(edit_window, text=translate(7) + ':', width=16)
    c2 = tk.Entry(edit_window, width=32)
    d1 = tk.Label(edit_window, text=translate(8) + ':', width=16)
    d2 = tk.Entry(edit_window, width=32)
    e2_pressed = tk.BooleanVar()
    e2_pressed.set(False)
    e2 = tk.Button(edit_window, text=translate(12), command=lambda: e2_pressed.set(True), width=32)
    f = tk.Label(edit_window, text='')
    g_pressed = tk.BooleanVar()
    g_pressed.set(False)
    g = tk.Button(edit_window, text=translate(13), command=lambda: g_pressed.set(True), width=50)
    a1.grid(row=0, column=0)
    a2.grid(row=0, column=1)
    b1.grid(row=1, column=0)
    b2.grid(row=1, column=1)
    c1.grid(row=2, column=0)
    c2.grid(row=2, column=1)
    d1.grid(row=3, column=0)
    d2.grid(row=3, column=1)
    e2.grid(row=4, column=1)
    f.grid(row=5, column=0, columnspan=2)
    g.grid(row=6, column=0, columnspan=2)
    information = get_information(name, _password)
    a2.insert(0, information[0])
    b2.insert(0, information[1])
    c2.insert(0, information[2])
    d2.insert(0, information[3])
    loop = tk.BooleanVar()
    loop.set(True)
    while loop.get():
        try:
            if a2.get() == '' or b2.get() == '' or c2.get() == '' or d2.get() == '' or \
                    (a2.get() in get_names(_password) and not a2.get() == name):
                g.config(state=tk.DISABLED)
                f.config(text=translate(45))
            else:
                g.config(state=tk.NORMAL)
                f.config(text='')
            if e2_pressed.get():
                e2_pressed.set(False)
                generate_window = tk.Tk()
                generate_window.title(translate(12) + ' - ' + translate(1))
                x = tk.Label(generate_window, text=translate(40))
                y = tk.Entry(generate_window, width=16)
                z_pressed = tk.BooleanVar()
                z_pressed.set(False)
                z = tk.Button(generate_window, text=translate(25), width=16, command=lambda: z_pressed.set(True))
                x.grid(row=0, column=0)
                y.grid(row=1, column=0)
                z.grid(row=2, column=0)
                loop2 = tk.BooleanVar()
                loop2.set(True)
                while loop2.get():
                    try:
                        try:
                            int(y.get())
                            z.config(state=tk.NORMAL)
                        except (ValueError, TypeError):
                            z.config(state=tk.DISABLED)
                        generate_window.update()
                        if z_pressed.get():
                            try:
                                y_int = int(y.get())
                                d2.delete(0, len(d2.get()) + 1)
                                d2.insert(0, generate_password(y_int))
                                loop2.set(False)
                                generate_window.destroy()
                            except (ValueError, TypeError):
                                pass
                    except tk.TclError:
                        loop2.set(False)
            edit_window.update()
            if g_pressed.get():
                g_pressed.set(False)
                names = get_names(_password)
                informations = get_informations(_password)
                informations[names.index(name)] = [a2.get(), b2.get(), c2.get(), d2.get()]
                change_information(informations)
                loop.set(False)
                edit_window.destroy()
        except tk.TclError:
            loop.set(False)


def init() -> str:
    translate_init()
    if os.path.exists('passwords.bin') and os.path.exists('config.txt'):
        backup_message()
        with open('config.txt', 'r') as config_file:
            config_file_content = config_file.readlines()
            init_window = tk.Tk()
            init_window.title(translate(19) + '! - ' + translate(1))
            a = tk.Label(init_window, text=translate(28))
            b = tk.Entry(init_window, show='*', width=32)
            c = tk.Button(init_window, text=translate(25), command=lambda: loop2.set(False))
            d = tk.Button(init_window, text=translate(41), command=forgot_password)
            a.grid(row=0, column=0)
            b.grid(row=1, column=0)
            c.grid(row=2, column=0)
            d.grid()
            loop = tk.BooleanVar()
            loop.set(True)
            while loop.get():
                loop2 = tk.BooleanVar()
                loop2.set(True)
                while loop2.get():
                    if b.get() == '' or ' ' in b.get():
                        c.config(state=tk.DISABLED)
                    else:
                        c.config(state=tk.NORMAL)
                    try:
                        init_window.update()
                    except tk.TclError:
                        sys.exit()
                password = b.get()
                salt = literal_eval(config_file_content[1].replace('\n', ''))
                hashed = str(hashlib.pbkdf2_hmac('sha512', password.encode(), salt, 128000))
                if hashed == config_file_content[0].replace('\n', ''):
                    init_window.destroy()
                    return password
                else:
                    messagebox.showerror(translate(29) + ' - ' + translate(1), translate(30))
    else:
        password_file_exists = os.path.exists('passwords.bin')
        config_file_exists = os.path.exists('config.txt')
        if not password_file_exists and not config_file_exists:
            return setup()
        else:
            recover()


def main() -> bool:
    global _password
    root = tk.Tk()
    root.title(translate(33) + ' - ' + translate(1))
    a_index = tk.IntVar()
    a_index.set(0)
    a2_pressed = tk.BooleanVar()
    a2_pressed.set(False)
    a2 = tk.Button(root, text='/\\', command=lambda: a2_pressed.set(True))
    a7_pressed = tk.BooleanVar()
    a7_pressed.set(False)
    a7 = tk.Button(root, text='\\/', command=lambda: a7_pressed.set(True))
    b1 = tk.Button(root, text=translate(16), command=add_information_dialog, width=32)
    b_selected = tk.IntVar()
    b_selected.set(0)
    b2_name = tk.StringVar()
    b2 = tk.Button(root, text=b2_name.get(), command=lambda: b_selected.set(1), width=32)
    b3_name = tk.StringVar()
    b3 = tk.Button(root, text=b3_name.get(), command=lambda: b_selected.set(2), width=32)
    b4_name = tk.StringVar()
    b4 = tk.Button(root, text=b4_name.get(), command=lambda: b_selected.set(3), width=32)
    b5_name = tk.StringVar()
    b5 = tk.Button(root, text=b5_name.get(), command=lambda: b_selected.set(4), width=32)
    b6_name = tk.StringVar()
    b6 = tk.Button(root, text=b6_name.get(), command=lambda: b_selected.set(5), width=32)
    b7_name = tk.StringVar()
    b7 = tk.Button(root, text=b7_name.get(), command=lambda: b_selected.set(6), width=32)
    b8_pressed = tk.BooleanVar()
    b8_pressed.set(False)
    b8 = tk.Button(root, text=translate(14), command=lambda: b8_pressed.set(True), width=32)
    c1 = tk.Label(root, text='', width=8)
    d1_pressed = tk.BooleanVar()
    d1_pressed.set(False)
    d1 = tk.Button(root, text=translate(2), command=lambda: d1_pressed.set(True), width=16)
    d2 = tk.Label(root, text=translate(4) + ':')
    d3 = tk.Label(root, text=translate(5) + '/' + translate(6) + ':')
    d4 = tk.Label(root, text=translate(7) + ':')
    d5 = tk.Label(root, text=translate(8) + ':')
    d6_pressed = tk.BooleanVar()
    d6_pressed.set(False)
    d6 = tk.Button(root, text=translate(9), command=lambda: d6_pressed.set(True), width=16)
    d7_pressed = tk.BooleanVar()
    d7_pressed.set(False)
    d7 = tk.Button(root, text=translate(12), command=lambda: d7_pressed.set(True), width=16)
    d8 = tk.Button(root, text=translate(15), command=open_about, width=16)
    e1_pressed = tk.BooleanVar()
    e1_pressed.set(False)
    e1 = tk.Button(root, text=translate(3), command=lambda: e1_pressed.set(True), width=32)
    e2_content = tk.StringVar()
    e2 = tk.Label(root, text=e2_content.get())
    e3_content = tk.StringVar()
    e3 = tk.Label(root, text=e3_content.get())
    e4_content = tk.StringVar()
    e4 = tk.Label(root, text=e4_content.get())
    e5_content = tk.StringVar()
    e5 = tk.Label(root, text=e5_content.get())
    e6_pressed = tk.BooleanVar()
    e6_pressed.set(False)
    e6_display = tk.IntVar()
    e6_display.set(10)
    e6_content = tk.StringVar()
    e6_content.set(translate(e6_display.get()))
    e6 = tk.Button(root, text=e6_content.get(), command=lambda: e6_pressed.set(True), width=32)
    e7_pressed = tk.BooleanVar()
    e7_pressed.set(False)
    e7 = tk.Button(root, text=translate(13), command=lambda: e7_pressed.set(True), width=32)
    e8 = tk.Label(root, text='')
    a2.grid(row=1, column=0)
    a7.grid(row=6, column=0)
    b1.grid(row=0, column=1)
    b2.grid(row=1, column=1)
    b3.grid(row=2, column=1)
    b4.grid(row=3, column=1)
    b5.grid(row=4, column=1)
    b6.grid(row=5, column=1)
    b7.grid(row=6, column=1)
    b8.grid(row=7, column=1)
    c1.grid(row=0, column=2)
    d1.grid(row=0, column=3)
    d2.grid(row=1, column=3)
    d3.grid(row=2, column=3)
    d4.grid(row=3, column=3)
    d5.grid(row=4, column=3)
    d6.grid(row=5, column=3)
    d7.grid(row=6, column=3)
    d8.grid(row=7, column=3)
    e1.grid(row=0, column=4)
    e2.grid(row=1, column=4)
    e3.grid(row=2, column=4)
    e4.grid(row=3, column=4)
    e5.grid(row=4, column=4)
    e6.grid(row=5, column=4)
    e7.grid(row=6, column=4)
    e8.grid(row=7, column=4)
    information = ['', '', '', '']
    loop = tk.BooleanVar()
    loop.set(True)
    while loop.get():
        try:
            root.update()
            names = get_names(_password)
            if a_index.get() <= 0:
                a2.config(state=tk.DISABLED)
            else:
                a2.config(state=tk.NORMAL)
            if len(names) <= a_index.get() + 6:
                a7.config(state=tk.DISABLED)
            else:
                a7.config(state=tk.NORMAL)
            if a2_pressed.get():
                a2_pressed.set(False)
                a_index.set(a_index.get() - 1)
            if a7_pressed.get():
                a7_pressed.set(False)
                a_index.set(a_index.get() + 1)
            b_list = []
            for i in range(6):
                try:
                    b_list.append(names[a_index.get() + i])
                except IndexError:
                    b_list.append('')
            if b_list[0] != '':
                b2.config(text=b_list[0], state=tk.NORMAL)
            else:
                b2.config(text='', state=tk.DISABLED)
            if b_list[1] != '':
                b3.config(text=b_list[1], state=tk.NORMAL)
            else:
                b3.config(text='', state=tk.DISABLED)
            if b_list[2] != '':
                b4.config(text=b_list[2], state=tk.NORMAL)
            else:
                b4.config(text='', state=tk.DISABLED)
            if b_list[3] != '':
                b5.config(text=b_list[3], state=tk.NORMAL)
            else:
                b5.config(text='', state=tk.DISABLED)
            if b_list[4] != '':
                b6.config(text=b_list[4], state=tk.NORMAL)
            else:
                b6.config(text='', state=tk.DISABLED)
            if b_list[5] != '':
                b7.config(text=b_list[5], state=tk.NORMAL)
            else:
                b7.config(text='', state=tk.DISABLED)
            if b8_pressed.get():
                b8_pressed.set(False)
                settings_menu()
            if d1_pressed.get():
                d1_pressed.set(False)
                root.destroy()
                loop.set(False)
                return True
            if b_selected.get() == 0:
                for element in (d2, d3, d4, d5, d6, d7):
                    element.grid_forget()
                selected = ''
            else:
                d2.grid(row=1, column=3)
                d3.grid(row=2, column=3)
                d4.grid(row=3, column=3)
                d5.grid(row=4, column=3)
                d6.grid(row=5, column=3)
                d7.grid(row=6, column=3)
                selected = names[a_index.get() + b_selected.get() - 1]
            if d6_pressed.get():
                d6_pressed.set(False)
                if information[3] != '':
                    copy(information[3], root)
                    messagebox.showinfo(translate(34) + ' - ' + translate(1), translate(35))
                else:
                    pass
            if d7_pressed.get():
                d7_pressed.set(False)
                if messagebox.askyesnocancel(translate(36) + ' - ' + translate(1), translate(37) + translate(38)):
                    generate_password_dialog(information[0])
            if selected != '':
                information = get_information(selected, _password)
                e2.config(text=selected)
                e3.config(text=information[1])
                e4.config(text=information[2])
                e2.grid(row=1, column=4)
                e3.grid(row=2, column=4)
                e4.grid(row=3, column=4)
                e5.grid(row=4, column=4)
                e6.grid(row=5, column=4)
                e7.grid(row=6, column=4)
                if e6_display.get() == 11:
                    e5.config(text=information[3])
                    e6_content.set(translate(e6_display.get()))
                    e6.config(text=e6_content.get())
                    if e6_pressed.get():
                        e6_pressed.set(False)
                        e6_display.set(10)
                else:
                    e5.config(text='****************')
                    e6_content.set(translate(e6_display.get()))
                    e6.config(text=e6_content.get())
                    if e6_pressed.get():
                        e6_pressed.set(False)
                        e6_display.set(11)
            else:
                information = ['', '', '', '']
                for element in (e2, e3, e4, e5, e6, e7):
                    element.grid_forget()

            if e1_pressed.get():
                e1_pressed.set(False)
                loop.set(False)
                root.destroy()
            if e7_pressed.get():
                e7_pressed.set(False)
                edit_dialog(selected)
            e8.config(text=get_string_time())
        except tk.TclError:
            loop.set(False)
    return False


if __name__ == '__main__':
    _loop = True
    while _loop:
        _language = []
        _password = init()
        _loop = main()
        del _password
