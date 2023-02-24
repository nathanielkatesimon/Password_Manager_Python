import mysql_functions as mysql
import rsa

db = mysql.Connection()


if db.CheckConnection():
    db.query('CREATE DATABASE IF NOT EXISTS password_manager')

    db = mysql.Connection(
        database='password_manager'
    )

    db.query('CREATE TABLE IF NOT EXISTS users ( user_id int(11) auto_increment not null, name varchar(50) not null, email varchar(50) not null, password longtext, primary key(user_id) )')
    db.query('CREATE TABLE IF NOT EXISTS ciphers ( cipher_id int(11) auto_increment not null, user_id int(11) not null, name varchar(50) not null, cipher_type varchar(50) not null, cipher_1 longtext, cipher_2 longtext, primary key(cipher_id) )')
    db.query('CREATE TABLE IF NOT EXISTS user_keys ( key_id int(11) auto_increment not null, user_id int(11) not null, name varchar(50) not null, P_Key longtext, primary key(key_id) )')




def check_conn():
    if not db.CheckConnection():
        return False
    else:
        return True


private_key = '2d2d2d2d2d424547494e205253412050524956415445204b45592d2d2d2d2d0a4d4949435877494241414b426751434e556665354b4f35747749584f645053647453676a6c456c61714b754c7a6839665253315979653544616f465056412b4b0a43726a69386864714947346977314b763558786a4951633150494a4a4d2b5a53664969334634546151754b674d514c52754f52414e4f3656547954486f4868670a795344353531546d7945677a706764464657463377396578707048474754314e704b355664594163773354447874523861566730753837656e514944415141420a416f47414a413777474779624f614851416e66524770526f6f33746f70427335656a696a784a6c514573476a613877334a6c6961686d787039473431447a30720a484f2b646e3466386a776155596a38494e306c6f707158617741783369344d39365374327565396774734667797766613458504c736b3439506e4941507a45360a6a5552465746526b592f3752716473614d42795168354e3261796b382f75626747464a69304f665048595045427345435251436e4d7837577041686a715475520a336a47714f6474623644354d7a614269457375526c2b4c595a78794f4b4c6a6c653471684256392f386b3765685967785568642f66574945716c646153782f360a3244623444347276442b67665a514939414e68674e4e2b3143784b33337657597a7452786b336d565578304e645268553753356b41383535656664396d6961750a76694f3137524c784e69322f7571644e6d673675594f3143445842366361776132514a45597a473337503136494b354a4d6877526550314550373245494971700a7953562f636b77612f2b6f456a65356f3633536b35537a4c344a742f34524a316e31556c7262525554354a447173554248772f685a4c2f4c33464b696b7555430a50416772435a5077563679724f4556354d555766792f74704161773146396946544462574737617471306347664d3039423378396e3664355a35777567724e530a494b437851494e30584f47454863707263514a4545454c6e6e30615a586d44364b582f325638667a7243414b6870594e313956564e77665976435757672f356e0a6d766f54444646766930416d52575651644d3062783142762b2f386f6532424b4736624a5950694d653333754c2b4d3d0a2d2d2d2d2d454e44205253412050524956415445204b45592d2d2d2d2d0a'

public_key = '2d2d2d2d2d424547494e20525341205055424c4943204b45592d2d2d2d2d0a4d49474a416f47424149315239376b6f376d334168633530394a32314b434f555356716f7134764f483139464c566a4a376b4e716755395544346f4b754f4c790a46326f6762694c4455712f6c66474d68427a5538676b6b7a356c4a38694c6358684e7043347141784174473435454130377056504a4d65676547444a49506e6e0a564f624953444f6d42305556595866443137476d6b63595a5055326b726c563167427a44644d504731487870574453377a74366441674d424141453d0a2d2d2d2d2d454e4420525341205055424c4943204b45592d2d2d2d2d0a'

def ChangePassword(user_data, current, new):
    response = Login(user_data.email, current, CP=True)
    if len(new) < 8:
        return 2
    elif response == 0:
        new_password = Encrypt(new)
        try:
            db.deleteQuery(f"UPDATE users SET password = '{new_password}' WHERE user_id = {user_data.user_id}")
            return 0
        except:
            return 1
    else:
        return 1

def DeleteKey(user_id, key_id):
    try:
        db.deleteQuery(f"DELETE FROM user_keys WHERE key_id = {key_id} and user_id = {user_id}")
        return 0
    except:
        return 1

def deleteCipher(id, user_id):
    try:
        db.deleteQuery(f'DELETE FROM ciphers WHERE cipher_id = {id} and user_id={user_id}')
        return 0
    except:
        return 1

def DecryptCipher(key_path, id, user_id):
    with open(key_path, "rb") as f:
        key = f.read()

    data = db.query(f"SELECT cipher_type, cipher_1, cipher_2 FROM ciphers WHERE cipher_id = {id} and user_id = {user_id}")

    text1 = Decrypt(data[0][1], key.hex())
    text2 = Decrypt(data[0][2], key.hex()) if data[0][0] == 'FULL' else ""

    if text1 == 1 or text2 == 1:
        return 1

    return (text1, text2, data[0][0])

def getCiphers(user_id):
    response = db.query(f"SELECT cipher_id, name FROM ciphers WHERE user_id = {user_id}")
    return response

def SelectKey(user_id):
    response = db.query(f"SELECT key_id, name FROM user_keys WHERE user_id = {user_id}")
    return response

def validateCipherName(name, user_id):
    response = db.query(f"SELECT name FROM ciphers WHERE name='{name}' and user_id={user_id}")
    return 1 if len(response) > 0 else 0

def AddCipher(data):
    if data.name == "" or data.text1 == "":
        return 1
    elif data.type == 'FULL' and data.text2 == "":
        return 1
    elif validateCipherName(data.name, data.user_id) == 1:
        return 2

    hex_key = db.query(f"SELECT P_Key FROM user_keys WHERE key_id = '{data.key_id}'")[0][0]

    cipher1 = Encrypt(data.text1, hex_key)
    cipher2 = Encrypt(data.text2, hex_key) if data.type == 'FULL' else ""

    try:
        db.query(f"INSERT INTO ciphers VALUES (DEFAULT, {data.user_id}, '{data.name}', '{data.type}', '{cipher1}', '{cipher2}')")
        return 0
    except:
        return 1

def ValidateKeyName(name, user_id):
    response = db.query(f"SELECT key_id FROM user_keys WHERE name='{name}' and user_id={user_id}")
    if len(response) > 0:
        return 1
    else:
        return 0

def GenerateKey(user_id, filepath, keyname):
    checkKey = ValidateKeyName(keyname, user_id)

    if checkKey == 1:
        return 1

    (pubkey, privkey) = rsa.newkeys(1024)

    with open(filepath + keyname + ".pem", "wb") as f:
        f.write(privkey.save_pkcs1('PEM'))

    public_key = pubkey.save_pkcs1('PEM').hex()

    try:
        db.query(f"INSERT INTO user_keys VALUES (DEFAULT, {user_id}, '{keyname}', '{public_key}')")
        return 0
    except:
        return 1

def EmailValidator(Email):
    response = db.query(f"SELECT name FROM users WHERE email = '{Email}'")

    if len(response) > 0:
        return 1
    elif Email.find("@") == -1 or Email.find('.com') == -1:
        return 5
    else:
        return 0

def PasswordValidator(password, cpassword):
    if password != cpassword:
        return 3
    elif len(password) < 8:
        return 4
    else:
        return 0

def Encrypt(text, key=public_key):
    cipher = rsa.encrypt(text.encode(), rsa.PublicKey.load_pkcs1(bytes.fromhex(key)))
    return cipher.hex()

def Decrypt(cipher, key=private_key):
    try:
        text = rsa.decrypt(bytes.fromhex(cipher), rsa.PrivateKey.load_pkcs1(bytes.fromhex(key))).decode()
        return text
    except:
        return 1


def Register(name, email, password, cpassword):
    if not name or not email or not password or not cpassword:
        return 2

    if PasswordValidator(password, cpassword) != 0:
        return PasswordValidator(password, cpassword)

    if EmailValidator(email) != 0:
        print(EmailValidator(email))
        return EmailValidator(email)

    password = Encrypt(password)
    db.query(f"INSERT INTO users VALUES (DEFAULT, '{name}', '{email}', '{password}')")
    return 0

def GetUserInfo(email):
    class User:
        def __init__(self, user_id, name, password, email):
            self.user_id = user_id
            self.name = name
            self.password = password
            self.email = email

    userInfo = db.query(f"SELECT user_id, name, password, email FROM users WHERE email ='{email}'")

    if len(userInfo) > 0:
        return User(userInfo[0][0], userInfo[0][1], userInfo[0][2], userInfo[0][3])
    else:
        return 1

def Login(email, password, CP = False):
    if not email or not password:
        return 2

    User = GetUserInfo(email)
    if User == 1:
        return 1
    elif Decrypt(User.password) != password:
        return 1
    elif CP:
        return 0
    else:
        return User
