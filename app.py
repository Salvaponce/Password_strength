import re
import math
from flask import Flask, render_template, request
from flask_bootstrap import Bootstrap4
import hashlib
import requests
import string
import secrets

app = Flask(__name__)

bootstrap = Bootstrap4(app)

def check_password(password):
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    r = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")

    for line in r.text.splitlines():
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            return int(count)
    return 0


def entropy(password):
    """Calculate the entropy of a password."""
    if len(password) == 0:
        return 0
    char_set = len(set(password))
    return math.log2(char_set) * len(password)


def criteria(password):
    length_criteria = len(password) >= 12 
    upper_criteria = re.search(r'[A-Z]', password) is not None
    lower_criteria = re.search(r'[a-z]', password) is not None
    digit_criteria = re.search(r'\d', password) is not None
    special_criteria = re.search(r'[!@#$%^&*(),.?":{}|<>]', password) is not None
    sequence_criteria = not re.search(r'(.)\1{2,}', password)  # No more than 2 repeating characters
    common_word_check = not in_list(password)  # Avoid common passwords

    criteria_met = [length_criteria, upper_criteria, lower_criteria, digit_criteria, 
                        special_criteria, sequence_criteria, common_word_check]
    return criteria_met


def calculate_strength(criteria_met, password):

    entropy_score = entropy(password)
    sum_criteria = sum(criteria_met)

    if entropy_score > 60:
        sum_criteria += 3  # Reward if entropy is high


    if sum_criteria >= 9:
        return f"Very Strong. Total: {entropy_score:.2f}/100."
    elif sum_criteria >= 7:
        return f"Strong. Total: {entropy_score:.2f}/100."
    elif sum_criteria >= 5:
        return f"Moderate. Total: {entropy_score:.2f}/100."
    else:
        return f"Weak. Total: {entropy_score:.2f}/100."    

    
def in_list(string):
    with open("10000-most-common-passwords.txt", "r") as file:
        passwordList = file.read().splitlines()
    
    return string in passwordList



def generate_password(length=12, u=True, l=True, d=True, s=True, n=False):
    if length < 1:
        raise ValueError("length must be >= 1")

    
    lowercase = string.ascii_lowercase    

    all_chars = lowercase
    password_chars = [secrets.choice(lowercase)]  # Ensure at least one lowercase letter
    if u:
        uppercase = string.ascii_uppercase
        all_chars += uppercase
        password_chars.append(secrets.choice(uppercase))
    if d:
        digits = string.digits
        all_chars += digits
        password_chars.append(secrets.choice(digits))
    if s:
        specials = "!@#$%^&*()-_=+[]{};:,.?/~"
        all_chars += specials
        password_chars.append(secrets.choice(specials))

    length -= len(password_chars)  # Adjust length for already added characters

    # Fill the rest
    password_chars += [secrets.choice(all_chars) for _ in range(length)]

    # Shuffle securely
    for i in range(len(password_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

    return "".join(password_chars)


@app.route('/', methods=['GET', 'POST'])
def index():
    strength = ""
    pwn_count = 0
    criteria_met = []
    active_tab = 'check'  # Default active tab
    if request.method == 'POST' and 'password' in request.form:
        password = request.form['password']
        criteria_met = criteria(password)
        strength = calculate_strength(criteria_met, password)
        pwn_count = check_password(password)     
        active_tab = 'check'  # Set active tab to check

        return render_template('index.html', strength=strength, pwn_count=pwn_count, criteria_met=criteria_met, active_tab=active_tab)
    elif request.method == 'POST':
        length = 12
        u, l, d, s, n = False, False, False, False, False
        try:
            length = int(request.form['length'])
        except (KeyError, ValueError):
            length = 12
        try:
            u = True if 'uppercase' in request.form else False
        except KeyError:
            u = False
        try:
            l = True if 'lowercase' in request.form else False
        except KeyError:
            l = False
        try:
            d = True if 'digits' in request.form else False
        except KeyError:
            d = False
        try:
            s = True if 'special_characters' in request.form else False
        except KeyError:
            s = False
        try:
            n = True if 'no_repeating' in request.form else False
        except KeyError:
            n = False

        print(length)
        active_tab = 'generate'  # Set active tab to generate
        generated_password = generate_password(length, u, l, d, s, n)
        print("Generated Password:", generated_password)
        return render_template('index.html', active_tab=active_tab, generated_password=generated_password)
    try:
        print(request.form['active_tab'])
    except KeyError:
        active_tab = 'check'
    
    return render_template('index.html', active_tab=active_tab)

if __name__ == '__main__':
    app.run(debug=True)
