from tkinter import *
from tkinter import ttk
from PIL import ImageTk, Image
import functions


root = Tk()
root.resizable(width=False, height=False)
root.iconbitmap("Images/icon.ico")
root.configure(bg="#3e8daa")

loginBG = ImageTk.PhotoImage(Image.open("Images/loginBG.png"))
regBG = ImageTk.PhotoImage(Image.open("Images/regBG.png"))
mainBG = ImageTk.PhotoImage(Image.open("Images/mainBG.png"))

refreshFrame = 0

class App:

    def __init__(self, root):
        self.root = root

        conn = functions.check_conn()
        if not conn:
            self.db_error()
        else:
            self.login()

        Style = ttk.Style()
        Style.theme_use("default")

        Style.configure("grey.TButton", background="#a6a7a7", foreground="white", borderwidth=0, width=10, font=("Segoe", 8, "bold"))
        Style.map("grey.TButton", background=[("active", "#a6a7a7")])

        Style.configure("odd.TButton", borderwidth=0, width=41, background="#2f7492", foreground="white", font=("Segoe", 10, "bold"))
        Style.map("odd.TButton", background=[("pressed", "#194b61")])

        Style.configure("even.TButton", borderwidth=0, width=41, background="#194b61", foreground="white", font=("Segoe", 10, "bold"))
        Style.map("even.TButton", background=[("pressed", "#2f7492")])

        Style.configure("odd_key.TButton", borderwidth=0, width=27, background="#2f7492", foreground="white", font=("Segoe", 10, "bold"))
        Style.map("odd_key.TButton", background=[("pressed", "#194b61")])

        Style.configure("even_key.TButton", borderwidth=0, width=27, background="#194b61", foreground="white", font=("Segoe", 10, "bold"))
        Style.map("even_key.TButton", background=[("pressed", "#2f7492")])

        Style.configure("link.TLabel", background="#3e8daa", foreground="white")
        Style.map("link.TLabel", foreground=[("active", "#a6a7a7")])

        Style.configure('setting.TButton', background='white', foreground='#305F72', borderwidth=0, width=18)
        Style.map('setting.TButton', background=[('pressed', 'white')])

    def login(self, event="", error=0):
        for i in self.root.winfo_children():
            i.destroy()
        self.root.title("Login")
        self.root.geometry("300x380+550+200")

        loginFrame = Frame(self.root)
        loginFrame.pack()

        BG = Label(loginFrame, image=loginBG)
        BG.pack()

        email = Entry(loginFrame, relief="flat", width=30, justify="center", fg="#3e8daa")
        email.place(x=62, y=223)

        password = Entry(loginFrame, relief="flat", show='*', width=30, justify="center", fg="#3e8daa")
        password.place(x=62, y=265)


        if error == 1:
            e = Label(loginFrame, text="incorrect username or password", bg='#3e8daa', fg='red')
            e.place(x=67, y=285)
        elif error == 2:
            e = Label(loginFrame, text="Fill up all input fields", bg='#3e8daa', fg='red')
            e.place(x=95, y=285)

        def login():
            response = functions.Login(email.get(), password.get())
            if response == 1:
                self.login(error=1)
            elif response == 2:
                self.login(error=2)
            else:
                self.main(user_data=response)



        loginBtn = ttk.Button(loginFrame, text="LOG IN", style="grey.TButton", command=login)
        loginBtn.place(x=120, y=310)

        createAccount = ttk.Label(loginFrame, text="Create Account", style="link.TLabel")
        createAccount.bind('<Button-1>', self.CreateAccount)
        createAccount.place(x=112, y=342)


    def CreateAccount(self, event="", error=0):
        for i in self.root.winfo_children():
            i.destroy()
        self.root.title("Register")

        regFrame = Frame(self.root)
        regFrame.pack()

        BG = Label(regFrame, image=regBG)
        BG.pack()

        name = Entry(regFrame, relief="flat", width=30, justify="center", fg="#3e8daa")
        name.place(x=62, y=110)

        email = Entry(regFrame, relief="flat", width=30, justify="center", fg="#3e8daa")
        email.place(x=62, y=155)

        password = Entry(regFrame, show='*', relief="flat", width=30, justify="center", fg="#3e8daa")
        password.place(x=62, y=205)

        confirm_password = Entry(regFrame, show='*', relief="flat", width=30, justify="center", fg="#3e8daa")
        confirm_password.place(x=62, y=255)

        if error == 1:
            e = Label(regFrame, text="email already used", bg='#3e8daa', fg='red')
            e.place(x=100, y=275)
        elif error == 2:
            e = Label(regFrame, text="Fill up all input fields", bg='#3e8daa', fg='red')
            e.place(x=95, y=275)
        elif error == 3:
            e = Label(regFrame, text="Passwords doesn't match", bg='#3e8daa', fg='red')
            e.place(x=87, y=275)
        elif error == 4:
            e = Label(regFrame, text="Password too short", bg='#3e8daa', fg='red')
            e.place(x=102, y=275)
        elif error == 5:
            e = Label(regFrame, text="Invalid email", bg='#3e8daa', fg='red')
            e.place(x=118, y=275)
        elif error == -1:
            e = Label(regFrame, text="Successfuly created account", bg='#3e8daa', fg='lime')
            e.place(x=78, y=275)


        def Register():
            response = functions.Register(name.get(), email.get(), password.get(), confirm_password.get())
            if response == 1:
                self.CreateAccount(error=1)
            elif response == 2:
                self.CreateAccount(error=2)
            elif response == 3:
                self.CreateAccount(error=3)
            elif response == 4:
                self.CreateAccount(error=4)
            elif response == 5:
                self.CreateAccount(error=5)
            else:
                self.CreateAccount(error=-1)


        regBtn = ttk.Button(regFrame, text="REGISTER", style="grey.TButton", command=Register)
        regBtn.place(x=120, y=300)

        login = ttk.Label(regFrame, text="login", style="link.TLabel")
        login.bind('<Button-1>', self.login)
        login.place(x=140, y=332)


    def refresh(self, master, user_data):
        state = "odd"

        for i in master.winfo_children():
            i.destroy()

        mainFrame2 = Frame(master, bg="#2f7492")
        mainFrame2.pack(fill=BOTH)

        myCanvas = Canvas(mainFrame2, bg="#2f7492", width=295, height=295)
        myCanvas.pack(fill=BOTH, side='left')
        myCanvas.config(highlightthickness=0)

        myCanvas.bind('<Configure>', lambda e: myCanvas.configure(scrollregion=myCanvas.bbox("all")))

        ciphers = functions.getCiphers(user_data.user_id)

        def _on_mouse_wheel(event):
            if len(ciphers) > 12:
                myCanvas.yview_scroll(-1 * int((event.delta / 120)), "units")

        myCanvas.bind_all("<MouseWheel>", _on_mouse_wheel)

        secondFrame = Frame(myCanvas, bg="#2f7492")

        myCanvas.create_window((0, 0), window=secondFrame, anchor="nw")

        cipher_widgets = []

        for i in ciphers:
            if state == "odd":
                e = ttk.Button(secondFrame, text=f"{i[1]}", style="odd.TButton")
                c = i[0]
                n = i[1]
                cipher_widgets.append((e, c, n))
                state="even"
            else:
                e = ttk.Button(secondFrame, text=f"{i[1]}", style="even.TButton")
                c = i[0]
                n = i[1]
                cipher_widgets.append((e, c, n))
                state="odd"

        def packWidgets(widget):
            widget[0].config(command=lambda: self.ConfigCipher(widget[1], user_data, widget[2]))
            widget[0].pack()

        for i in cipher_widgets:
            packWidgets(i)

    def ConfigCipher(self, cipher_id, user_data, name):
        from tkinter import filedialog as fd
        global refreshFrame

        def select_key():
            filepath = fd.askopenfilename()
            return filepath


        addWin = Toplevel(self.root)
        addWin.iconbitmap("Images/icon.ico")
        addWin.config(bg="#3e8daa")
        addWin.geometry("233x130+600+300")
        addWin.title(f"configure {name}")
        addWin.resizable(height=False, width=False)
        addWin.grab_set()

        e = Label(addWin, text=name, bg="#3e8daa", fg="white", font=('segoe', 14, 'bold'))
        e.pack()

        def decrypt():
            key_path = select_key()
            response = functions.DecryptCipher(key_path, cipher_id, user_data.user_id) if key_path != "" else 2

            if response == 1:
                addWin.destroy()
                self.DecryptionFailed()
            elif response == 2:
                pass
            else:
                addWin.destroy()
                self.ShowDecrypted(response)

        def delete():
            response = functions.deleteCipher(cipher_id, user_data.user_id)
            if response == 0:
                addWin.destroy()
                self.refresh(refreshFrame, user_data)


        decrypt = Button(addWin, text="Decrypt", relief='flat', bg="white", fg="#3e8daa", width=15, command=decrypt)
        decrypt.pack(pady=5)

        delete = Button(addWin, text="Delete", relief='flat', bg='white', fg="#3e8daa", width=15, command=delete)
        delete.pack()

        cancel = Button(addWin, text="Cancel", relief='flat', bg='white', fg='#3e8daa', width=15, command=lambda: addWin.destroy())
        cancel.pack(pady=5)

    def DecryptionFailed(self):
        ErrorWin = Toplevel(self.root)
        ErrorWin.iconbitmap("Images/icon.ico")
        ErrorWin.title("ERROR")
        ErrorWin.config(bg="#3e8daa")
        ErrorWin.geometry("+600+300")
        ErrorWin.resizable(height=False, width=False)

        e = Label(ErrorWin, text="ERROR: Decryption Failed", font=('segoe', 15, 'bold'), fg='red', bg="#3e8daa")
        e.pack()




    def db_error(self):
        for i in self.root.winfo_children():
            i.destroy()

        ErrorWin = Frame(self.root)
        ErrorWin.pack(fill=BOTH)
        self.root.title("ERROR")
        self.root.geometry("+600+300")

        e = Label(ErrorWin, text="ERROR: Cannot Connect to mysql database", font=('segoe', 15, 'bold'), fg='red', bg="#3e8daa")
        e.pack()


    def ShowDecrypted(self, data):
        ErrorWin = Toplevel(self.root)
        ErrorWin.iconbitmap("Images/icon.ico")
        ErrorWin.title("Success")
        ErrorWin.geometry("+600+300")
        ErrorWin.config(bg="#3e8daa")
        ErrorWin.resizable(height=False, width=False)

        if data[2] == 'FULL':
            e = Label(ErrorWin, text="username:", font=('segoe', 12, 'bold'), bg="#3e8daa")
            e.pack()
            e = Label(ErrorWin, text=data[1], font=('segoe', 15, 'bold'), fg='lime', bg="#3e8daa")
            e.pack(pady=5, padx=20)

        e = Label(ErrorWin, text="password:", font=('segoe', 12, 'bold'), bg="#3e8daa")
        e.pack()
        e = Label(ErrorWin, text=data[0], font=('segoe', 15, 'bold'), fg='lime', bg="#3e8daa")
        e.pack(pady=5, padx=20)

    def AddCipher(self, user_data=""):
        addWin = Toplevel(self.root)
        addWin.iconbitmap("Images/icon.ico")
        addWin.config(bg="#3e8daa")
        addWin.geometry("233x150+600+300")
        addWin.title("Type")
        addWin.grab_set()
        addWin.resizable(height=False, width=False)

        class Data:
            def __init__(self, type, user_id):
                self.type = type
                self.name = ""
                self.user_id = user_id
                self.key_id = ""
                self.text1 = ""
                self.text2 = ""


        def proceed(type):
            addWin.destroy()
            self.EnterText(Data(type, user_data.user_id), user_data)


        full_account = Button(addWin, text="Username and Password", relief='flat', fg="#3e8daa", bg='white', width=20, command=lambda: proceed("FULL"))
        password_only = Button(addWin, text="Password only", relief='flat', fg="#3e8daa", bg='white', width=20, command=lambda: proceed("HALF"))
        cancel = Button(addWin, text="Cancel", relief='flat', fg="#3e8daa", bg='white', width=20, command=lambda: addWin.destroy())

        full_account.pack(pady=10)
        password_only.pack(pady=10)
        cancel.pack(pady=10)

    def EnterText(self, data, user_data):
        addWin = Toplevel(self.root)
        addWin.iconbitmap("Images/icon.ico")
        addWin.config(bg="#3e8daa")
        addWin.resizable(height=False, width=False)
        if data.type == 'FULL':
            addWin.geometry("233x250+600+300")
        else:
            addWin.geometry("233x200+600+300")
        title = "Account" if data.type == 'FULL' else "Password"
        addWin.title(f"Enter {title} to encrypt")
        addWin.grab_set()

        if data.type == 'FULL':
            e = Label(addWin, text="Account name", bg="#3e8daa", fg="white")
            e.pack()
        else:
            e = Label(addWin, text="password name", bg="#3e8daa", fg="white")
            e.pack()

        name = Entry(addWin, width=30, justify='center')
        name.pack(pady=5)

        if data.type == 'FULL':
            e = Label(addWin, text="username", bg="#3e8daa", fg="white")
            e.pack()
            username = Entry(addWin, width=30, justify='center')
            username.pack(pady=5)
        e = Label(addWin, text="password", bg="#3e8daa", fg="white")
        e.pack()
        password = Entry(addWin, width=30, justify='center')
        password.pack(pady=5)

        def submit():
            if data.type == 'FULL':
                data.text2 = username.get()
                data.text1 = password.get()
                data.name = name.get()
            else:
                data.name = name.get()
                data.text1 = password.get()

            addWin.destroy()
            self.SelectKey(data, user_data)

        submit = Button(addWin, text="Encrypt", relief='flat', width=8, bg="white", fg='#3e8daa', command=submit)
        submit.pack(pady=10)

        cancel = Button(addWin, text="Cancel", relief='flat', width=8, bg="white", fg='#3e8daa', command=lambda: addWin.destroy())
        cancel.pack()


    def SelectKey(self, data, user_data):
        addWin = Toplevel(self.root)
        addWin.iconbitmap("Images/icon.ico")
        addWin.config(bg="#3e8daa")
        addWin.geometry("233x150+600+300")
        addWin.title("Select Key")
        addWin.grab_set()
        addWin.resizable(height=False, width=False)

        selectLabel = Label(addWin, text="Select key for encryption", bg="#3e8daa", fg='white', font=('segoe', 10, 'bold'))
        selectLabel.pack(pady=(5, 3))

        master = Frame(addWin)
        master.config(highlightthickness=1)
        master.pack(fill=BOTH, padx=20, pady=(0, 10))

        state = "odd"

        for i in master.winfo_children():
            i.destroy()

        mainFrame2 = Frame(master, bg="#2f7492")
        mainFrame2.pack(fill=BOTH)

        myCanvas = Canvas(mainFrame2, bg="#2f7492", width=233, height=295)
        myCanvas.pack(fill=BOTH, side='left')
        myCanvas.config(highlightthickness=0)

        myCanvas.bind('<Configure>', lambda e: myCanvas.configure(scrollregion=myCanvas.bbox("all")))

        response = functions.SelectKey(user_data.user_id)

        def _on_mouse_wheel(event):
            if len(response) > 4:
                myCanvas.yview_scroll(-1 * int((event.delta / 120)), "units")

        myCanvas.bind_all("<MouseWheel>", _on_mouse_wheel)

        secondFrame = Frame(myCanvas, bg="#2f7492")

        myCanvas.create_window((0, 0), window=secondFrame, anchor="nw")


        def MakeAddCipher(key_id):
            data.key_id = key_id
            response = functions.AddCipher(data)

            if response == 1:
                addWin.destroy()
                self.refresh(refreshFrame, user_data)
                self.AddCipherError()
            elif response == 2:
                addWin.destroy()
                self.refresh(refreshFrame, user_data)
                self.AddCipherError(2)
            else:
                addWin.destroy()
                self.refresh(refreshFrame, user_data)

        keys = []

        for i in response:
            if state == "odd":
                e = ttk.Button(secondFrame, text=f"{i[1]}", style="odd_key.TButton")
                k = i[0]
                keys.append((e, k))
                state="even"
            else:
                e = ttk.Button(secondFrame, text=f"{i[1]}", style="even_key.TButton")
                k = i[0]
                keys.append((e, k))
                state="odd"

        def packWidgets(widget):
            widget[0].config(command=lambda: MakeAddCipher(widget[1]))
            widget[0].pack()

        for i in keys:
            packWidgets(i)

    def generateKey(self, user, master):
        from tkinter import filedialog as fd
        import os
        pc_user = os.environ.get('USERNAME')
        default_save_dir = "C:/Users/" + pc_user + "/Documents/"

        def select_path(path_widget):
            filepath = fd.askdirectory()
            if filepath != "":
                path_widget.delete(0, END)
                path_widget.insert(string = filepath + '/', index=0)


        key_info = Toplevel(self.root)
        key_info.iconbitmap('Images/icon.ico')
        key_info.title("Generate Key")
        key_info.resizable(width=False, height=False)
        key_info.geometry("233x110+600+300")
        key_info.grab_set()
        key_info.configure(bg='#3e8daa')

        key_name_label = Label(key_info, text="Key Name", bg="#3e8daa", fg='white')
        key_name_label.grid(row=0, column=1, columnspan=7)

        key_name = Entry(key_info, width=35 , bg='#194b61', fg="white")
        key_name.grid(row=1, column=1, columnspan=7, padx=10)
        key_name.insert(string="privatekey", index=0)

        key_location = Entry(key_info, bg='#194b61', fg='white', width=24)
        key_location.grid(row=2, column=1, columnspan=6, padx=(10, 0))
        key_location.insert(string=default_save_dir, index=0)

        browse = Button(key_info, text="Browse", relief="flat", bg='white', fg='#305F72', width=9, font=("Segoe", 7, 'bold'), command=lambda: select_path(key_location))
        browse.grid(row=2, column=7, padx=(0, 10))


        def Generate():
            response = functions.GenerateKey(user.user_id, key_location.get(), key_name.get())
            if response == 0:
                key_info.destroy()
            else:
                key_info.destroy()
                self.KeyGenError()


        generate = Button(key_info, text="Generate", bg='white', width=8, fg='#305F72', relief="flat", command=Generate)
        generate.grid(row=3, column=7, padx=(0, 10), pady=10)

        cancel = Button(key_info, text="Cancel", bg='white', width=8, fg='#305F72', relief="flat", command=key_info.destroy)
        cancel.grid(row=3, column=1, pady=10)

    def KeyGenError(self):
        ErrorWin = Toplevel(self.root)
        ErrorWin.iconbitmap("Images/icon.ico")
        ErrorWin.title("ERROR")
        ErrorWin.config(bg="#3e8daa")
        ErrorWin.geometry("+600+300")
        ErrorWin.resizable(height=False, width=False)


        e = Label(ErrorWin, text="ERROR: A key with that name already exist", font=('segoe', 15, 'bold'), fg='red', bg="#3e8daa")
        e.pack()

    def AddCipherError(self, error=1):
        ErrorWin = Toplevel(self.root)
        ErrorWin.iconbitmap("Images/icon.ico")
        ErrorWin.title("ERROR")
        ErrorWin.config(bg="#3e8daa")
        ErrorWin.geometry("+600+300")
        ErrorWin.resizable(height=False, width=False)

        errorType = "ERROR: please fillup all input fields" if error == 1 else "ERROR: You already have an ecnrypted data with that name"

        e = Label(ErrorWin, text=errorType, font=('segoe', 15, 'bold'), fg='red', bg="#3e8daa")
        e.pack()


    def manage_keys(self, user_data):
        addWin = Toplevel(self.root)
        addWin.iconbitmap("Images/icon.ico")
        addWin.config(bg="#3e8daa")
        addWin.geometry("233x150+600+300")
        addWin.title("Select Key")
        addWin.grab_set()
        addWin.resizable(height=False, width=False)

        selectLabel = Label(addWin, text="Select key to delete", bg="#3e8daa", fg='white', font=('segoe', 10, 'bold'))
        selectLabel.pack(pady=(5, 3))

        master = Frame(addWin)
        master.config(highlightthickness=1)
        master.pack(fill=BOTH, padx=20, pady=(0, 10))

        state = "odd"

        for i in master.winfo_children():
            i.destroy()

        mainFrame2 = Frame(master, bg="#2f7492")
        mainFrame2.pack(fill=BOTH)

        myCanvas = Canvas(mainFrame2, bg="#2f7492", width=233, height=295)
        myCanvas.pack(fill=BOTH, side='left')
        myCanvas.config(highlightthickness=0)

        myCanvas.bind('<Configure>', lambda e: myCanvas.configure(scrollregion=myCanvas.bbox("all")))

        response = functions.SelectKey(user_data.user_id)

        def _on_mouse_wheel(event):
            if len(response) > 4:
                myCanvas.yview_scroll(-1 * int((event.delta / 120)), "units")

        myCanvas.bind_all("<MouseWheel>", _on_mouse_wheel)

        secondFrame = Frame(myCanvas, bg="#2f7492")

        myCanvas.create_window((0, 0), window=secondFrame, anchor="nw")

        def manage_key(key_id, name):
            addWin.destroy()
            self.delete_key(key_id, user_data, name)

        keys = []

        for i in response:
            if state == "odd":
                e = ttk.Button(secondFrame, text=f"{i[1]}", style="odd_key.TButton")
                k = i[0]
                n = i[1]
                keys.append((e, k, n))
                state="even"
            else:
                e = ttk.Button(secondFrame, text=f"{i[1]}", style="even_key.TButton")
                k = i[0]
                n = i[1]
                keys.append((e, k, n))
                state="odd"

        def packWidgets(widget):
            widget[0].config(command=lambda: manage_key(widget[1], widget[2]))
            widget[0].pack()

        for i in keys:
            packWidgets(i)

    def delete_key(self, key_id, user_data, name):
        addWin = Toplevel(self.root)
        addWin.iconbitmap("Images/icon.ico")
        addWin.config(bg="#3e8daa")
        addWin.title("Select Key")
        addWin.grab_set()
        addWin.geometry("+600+300")
        addWin.resizable(height=False, width=False)

        def delete():
            functions.DeleteKey(user_data.user_id, key_id)
            addWin.destroy()
            self.manage_keys(user_data)

        def cancel():
            addWin.destroy()
            self.manage_keys(user_data)

        e = Label(addWin, text=f'Are you sure you want to delete {name}?', bg="#3e8daa", fg="white", font=('segoe', 12, 'bold'))
        e.pack(pady=5, padx=15)
        ok = Button(addWin, text="Delete", relief='flat', bg="white", fg="#3e8daa", width=20, command=delete)
        ok.pack(padx=20)
        cancel = Button(addWin, text="Cancel", relief='flat', bg="white", fg="#3e8daa", width=20, command=cancel)
        cancel.pack(padx=20, pady=(5, 10))

    def change_password(self, user_data):
        addWin = Toplevel(self.root)
        addWin.iconbitmap("Images/icon.ico")
        addWin.title('Change Password')
        addWin.resizable(height=False, width=False)
        addWin.geometry("+600+300")
        addWin.config(bg="#3e8daa")

        currentPass_label = Label(addWin, text="Enter current password", bg="#3e8daa", fg="white")
        currentPass_label.pack(pady=(10, 0))
        current_pass = Entry(addWin, width=30, show='*', justify='center')
        current_pass.pack(pady=5, padx=10)
        newPass_label = Label(addWin, text="Enter new password", bg="#3e8daa", fg="white")
        newPass_label.pack()
        new_pass = Entry(addWin, width=30, show='*', justify='center')
        new_pass.pack(pady=5)

        def ChangePass():
                response = functions.ChangePassword(user_data, current_pass.get(), new_pass.get())
                if response == 0:
                    addWin.destroy()
                else:
                    addWin.destroy()
                    self.changePassError(response)

        submit = Button(addWin, text="change password", bg="white", fg="#3e8daa", relief='flat', width=14, command=ChangePass)
        submit.pack()
        cancel = Button(addWin, text="cancel", bg="white", fg="#3e8daa", relief='flat', width=14, command=addWin.destroy)
        cancel.pack(pady=(5, 10))

    def changePassError(self, error):
        ErrorWin = Toplevel(self.root)
        ErrorWin.iconbitmap("Images/icon.ico")
        ErrorWin.title("ERROR")
        ErrorWin.config(bg="#3e8daa")
        ErrorWin.geometry("+600+300")
        ErrorWin.resizable(height=False, width=False)

        errorType = "ERROR: Current password is incorrect" if error == 1 else "ERROR: Password must be 8 characters or more"

        e = Label(ErrorWin, text=errorType, font=('segoe', 15, 'bold'), fg='red', bg="#3e8daa")
        e.pack()


    def Settings(self, data):
        for i in self.root.winfo_children():
            i.destroy()

        self.root.title("Settings")
        self.root.geometry("300x200")

        Setting_frame = Frame(self.root, bg='#3e8daa', height=300, width=300)
        Setting_frame.grid(row=0, rowspan=3, padx=95, pady=5)

        ChangePassword_button = ttk.Button(Setting_frame, style="setting.TButton", text="Change Password", command=lambda: self.change_password(data))
        ChangePassword_button.grid(row=1, column=0, pady=5)

        ManageKeys_button = ttk.Button(Setting_frame, style="setting.TButton", text="Delete Keys", command=lambda: self.manage_keys(data))
        ManageKeys_button.grid(row=2, column=0, pady=5)

        Back_button = ttk.Button(Setting_frame, style="setting.TButton", text="Back", command=lambda: self.main(user_data=data))
        Back_button.grid(row=3, column=0, pady=5)

    def main(self, user_data):
        for i in self.root.winfo_children():
            i.destroy()
        global refreshFrame
        self.root.title(f"Hello {user_data.name}")
        self.root.geometry("405x360")
        mainFrame = Frame(self.root)
        mainFrame.pack()

        BG = Label(mainFrame, image=mainBG)
        BG.pack()

        PasswordsFrame = Frame(mainFrame, bg="#2f7492")
        refreshFrame = PasswordsFrame
        PasswordsFrame.place(x=99, y=52)

        self.refresh(PasswordsFrame, user_data)


        add = Button(mainFrame, text="ADD", relief="flat", bg='white', fg="#3e8daa", font=("Segoe", 8, "bold"), width="11", command=lambda: self.AddCipher(user_data))
        add.place(x=7, y=138)

        Settings = Button(mainFrame, text="SETTINGS", relief="flat", bg='white', fg="#3e8daa", font=("Segoe", 8, "bold"), width="11", command=lambda: self.Settings(user_data))
        Settings.place(x=7, y=169)

        Generate = Button(mainFrame, text="GENERATE KEY", relief="flat", bg='white', fg="#3e8daa", font=("Segoe", 8, "bold"), width="11", command=lambda: self.generateKey(user_data, PasswordsFrame))
        Generate.place(x=7, y=202)

        Logout = Button(mainFrame, text="LOGOUT", relief="flat", bg='white', fg="#3e8daa", font=("Segoe", 8, "bold"), width="11", command=self.login)
        Logout.place(x=7, y=234)


App(root)
root.mainloop()
