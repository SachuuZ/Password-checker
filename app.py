from flask import Flask, render_template, request
from zxcvbn import zxcvbn
import hashlib
import requests

app = Flask(__name__)

def check_pwned_password(password):
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        response = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}')
        if response.status_code != 200:
            return None
        for line in response.text.splitlines():
            if line.startswith(suffix):
                return int(line.split(':')[1])
        return 0
    except:
        return None

def strength_label(score):
    return {
        0: "Very Weak 🔓",
        1: "Weak ⚠️",
        2: "Moderate 🟡",
        3: "Good 🔐",
        4: "Strong ✅"
    }.get(score, "Unknown")

def custom_suggestions(score):
    return {
        0: [
            "Use at least 12 characters.",
            "Avoid common passwords like '123456'.",
            "Add uppercase, numbers, and symbols.",
        ],
        1: [
            "Avoid names or dictionary words.",
            "Use a random passphrase.",
            "Make it longer and less predictable.",
        ],
        2: [
            "Avoid keyboard patterns like 'qwerty'.",
            "Use 14+ characters for better strength.",
        ],
        3: [
            "Consider adding symbols or digits.",
            "Don't reuse passwords on other sites.",
        ]
    }.get(score, [])

@app.route("/", methods=["GET", "POST"])
def index():
    password = ""
    result = {}
    pwned = None
    strength = ""
    custom = []

    if request.method == "POST":
        password = request.form["password"]
        result = zxcvbn(password)
        pwned = check_pwned_password(password)
        score = result['score']
        strength = strength_label(score)
        custom = custom_suggestions(score)

    return render_template("index.html",
                           password=password,
                           result=result,
                           pwned=pwned,
                           strength=strength,
                           custom=custom)

if __name__ == "__main__":
    app.run()

