import re
import math
from flask import Flask, render_template, request
from flask_bootstrap import Bootstrap4

app = Flask(__name__)

bootstrap = Bootstrap4(app)

def entropy(password):
    """Calculate the entropy of a password."""
    if len(password) == 0:
        return 0
    char_set = len(set(password))
    return math.log2(char_set) * len(password)

def password_strength(password):
    length_criteria = len(password) >= 12  # Minimum length is now 12 characters
    upper_criteria = re.search(r'[A-Z]', password) is not None
    lower_criteria = re.search(r'[a-z]', password) is not None
    digit_criteria = re.search(r'\d', password) is not None
    special_criteria = re.search(r'[!@#$%^&*(),.?":{}|<>]', password) is not None
    sequence_criteria = not re.search(r'(.)\1{2,}', password)  # No more than 2 repeating characters
    common_word_check = not in_list(password)  # Avoid common passwords
    entropy_score = entropy(password)

    criteria_met = sum([length_criteria, upper_criteria, lower_criteria, digit_criteria, 
                        special_criteria, sequence_criteria, common_word_check])

    # Adding rules for entropy
    if entropy_score < 60:
        criteria_met -= 1  # Penalize if entropy is low

    if criteria_met >= 7:
        return "Very Strong"
    elif criteria_met >= 5:
        return "Strong"
    elif criteria_met >= 3:
        return "Moderate"
    else:
        return "Weak"

    
def in_list(string):
    with open("10000-most-common-passwords.txt", "r") as file:
        passwordList = file.read().splitlines()
    
    return string in passwordList


@app.route('/', methods=['GET', 'POST'])
def index():
    strength = ""
    if request.method == 'POST':
        password = request.form['password']
        strength = password_strength(password)
    return render_template('index.html', strength=strength)

if __name__ == '__main__':
    app.run(debug=True)
