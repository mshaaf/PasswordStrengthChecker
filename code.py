import math
import re
import random
import string

#The 200 most common passwords of 2022 according to Nord VPN
cm_passwords = [
    "123456", "admin", "12345678", "123456789", "1234", "12345", "password", "123", "Aa123456", "1234567890",
    "1234567", "123123", "111111", "Password", "12345678910", "000000", "admin123", "1111", "P@ssw0rd", "root",
    "654321", "qwerty", "Pass@123", "112233", "102030", "ubnt", "abc123", "Aa@123456", "abcd1234", "1q2w3e4r",
    "123321", "qwertyuiop", "87654321", "987654321", "Eliska81", "123123123", "11223344", "0987654321", "demo",
    "12341234", "qwerty123", "Admin@123", "1q2w3e4r5t", "11111111", "pass", "Demo@123", "azerty", "admintelecom",
    "Admin", "123meklozed", "666666", "0123456789",
    "121212", "1234qwer", "admin@123", "1qaz2wsx", "123456789a", "Aa112233", "asdfghjkl", "Password1", "888888",
    "admin1", "test", "Aa123456@", "asd123", "qwer1234", "123qwe", "202020", "asdf1234", "a123456", "Abcd@1234",
    "12344321", "aa123456", "1122334455", "Abce1234", "guest", "88888888", "Admin123", "secret", "1122",
    "admin1234", "administrator", "Password@123", "q1w2e3r4", "q1w2e3r4", "10203040", "5555555", "zxcvbnm",
    "welcome", "Abcd@123", "Welcome@123", "minecraft", "101010", "Pass@1234", "123654", "123456a", "India@123",
    "Ar123455", "159357", "qwe123", "54321", "password1", "1029383756", "1234567891", "vodafone", "jimjim30",
    "Cindylee1", "1111111111", "azertuiop", "999999", "adminHW", "10203", "gvt12345", "12121212", "12345678901",
    "222222", "7777777", "12345678900", "Kumar@123", "147258", "qwerty12345", "asdasd", "abc12345", "bismillah",
    "Heslo1234", "1111111", "a123456789", "iloveyou", "Passw0rd", "aaaaaaa", "Flores123", "12qwaszx", "Welcome1",
    "password123", "123mudar", "123456aA@", "123qweasd", "868689849", "1234554321", "motorola", "q1w2e3r4t5",
    "1234512345", "undefined", "1q2w3e", "a1b2c3d4", "admin123456", "2402301978", "Qwerty123", "1qazxsw2",
    "test123", "Adam2312", "Password123", "1234567899", "Aa195043", "Test@123", "111111111", "admin12345",
    "zaq12wsx", "adminadmin", "ADMIN", "1234abcd", "Menara", "123abc", "theworldinyourhand", "123456a@", "Aa102030",
    "987654", "Mm123456", "p@ssw0rd", "qwerty1234", "Abc@1234", "121212", "1a2b3c4d", "123456789", "changeme",
    "123456789", "studnet", "senha123", "1234567a", "user1234", "abc123456", "master", "12345qwert", "1234561",
    "adminisp", "azerty123", "pakistan", "aaaaaaaa", "a1234567", "P@$$w0rd", "qwerty123456", "55555", "lol12345",
    "Aa12345678", "999999999", "P@55w0rd", "786786", "asdasd123", "test1234", "samsung"
]



def is_common_password(password):
    return password in cm_passwords 
   

def pwd_str(password):
    # Length score
    length_score = min(len(password) / 12, 1) * 5
    
    # Complexity Score
    complex_score = 0
    if len(password) >= 13 and len(set(password)) >= len(password) / 2:
        complex_score += 8
    elif len(password) <= 12 and any(char.isalpha() for char in password) and any(char.isdigit() for char in password) and not password.isalnum():
        complex_score += 4
    else:
        complex_score += 0

    total_score = (length_score + complex_score)
    
    if total_score < 7:
        password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
    
    return min(total_score, 10), password


    
def time_crack(password, attempts = 1000000000):
    total_comb = 62 ** len(password)
    sec_crack = total_comb / attempts
    
    if sec_crack < 60:
        return sec_crack, 'seconds'
    elif sec_crack < 3600:
        timeto_crack = sec_crack / 60
        return timeto_crack, 'minutes'
    elif sec_crack / 3600 < 31536000:
        timeto_crack = sec_crack / 3600
        return timeto_crack, 'hours'
    else:
        return "It is nearly impossible for a hacker to guess your password, good job"
    

def main():
    password = input("Hello, enter your password and I will give you a score rating and tell you how long it would take a hacker to find it out: ")
    if is_common_password(password):
        print("YOUR PASSWORD IS ONE OF THE MOST COMMON PASSWORDS IN THE WORLD! YOU MUST CHANGE THIS PASSWORD TO SOMETHING MORE SECURE IMMEDIATELY! CALL THE BANK, CALL THE FBI, CALL THE RED CROSS, TELL THEM YOU HAVE AN IDIOTIC PASSWORD AND THEY WILL GIVE YOU THE HELP YOU NEED")
    print("Input password:", password)
    
    strength_score, new_password = pwd_str(password)
    if strength_score < 7:
        print(f"Your password strength rating is {round(strength_score, 2)}. Your password is weak. We have generated a new password for you.") 
        print("Generated password:", new_password)
    else:
        print("Your password strength rating is ", round(strength_score, 2))
    time_result = time_crack(password)
    if isinstance(time_result, tuple):
        if len(time_result) == 2:
            time, unit = time_result
            print(f"It would take a hacker {round(time, 2)} {unit} to crack your password. ")
        else:
            time, unit, message = time_result
            print(f"It would take a hacker {round(time, 2)} {unit} to crack your password.")
            print(message)
    else:
        print(time_result)

   
main()
