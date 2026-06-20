# Password Security Analyzer

This is a Python tool I built to check password risk in a safe way. It does not crack passwords, save passwords, or send passwords to any website.

This project was developed as part of a Studio 2 group project at Noroff University College in collaboration with four fellow students. Through this project, I gained hands-on experience in Python programming, password security analysis, risk assessment, and secure coding practices.

## What the project does

The tool checks a password and gives a score, rating, findings, and recommendations. It looks for simple problems that people often miss, such as short length, common words, keyboard patterns, repeated characters, number sequences, and personal information.

The goal is not to say that a password is perfect. The goal is to show visible weaknesses and help the user make a better password.

## Main features

* Checks password length
* Estimates entropy in bits
* Finds common password words such as password, admin, welcome, and qwerty
* Finds keyboard patterns such as qwerty and 12345
* Finds simple number or letter sequences
* Finds repeated characters
* Checks if lowercase, uppercase, and numbers are used
* Can warn if the password contains personal details such as a name, city, year, school, or employer
* Masks the password in the final report
* Gives a rating: critical, weak, moderate, or strong
* Runs locally with no extra Python packages

## Why I built it this way

Passwords are sensitive, so I kept the design simple and safe.

This tool:

* does not crack passwords
* does not collect passwords
* does not save passwords
* does not send passwords to an API
* does not print the full password in the report

This makes the project better for a cybersecurity portfolio because it shows technical work and responsible thinking at the same time.

## Files in this project

```text
password-security-analyzer/
  README.md
  GITHUB_UPLOAD_GUIDE.md
  password_analyzer.py
  .gitignore
```

## Requirements

* Python 3.10 or newer
* No extra packages needed

## How to run it

Open the folder in a terminal and run:

```powershell
python password_analyzer.py --demo
```

Check one password:

```powershell
python password_analyzer.py --password "CorrectHorseBatteryStaple2026!"
```

Check a password with personal context:

```powershell
python password_analyzer.py --password "Oslo2026!" --context "Oslo,2026,Shimon"
```

The context part is optional. It is useful when I want the tool to warn about names, cities, years, or other personal words.

## Example output

```text
Password Security Report
============================
Password: pa*******23
Rating: critical
Score: 15/100
Estimated entropy: 56.87 bits

Findings
- Password is shorter than the recommended 12 characters.
- Password appears in or closely resembles a common password pattern.
- Password lacks character diversity.

Recommendations
- Avoid common or previously leaked passwords.
- Mix lowercase, uppercase, numbers, and symbols where allowed.
- Use at least 14 characters for important accounts.
```

## How the score works

The tool starts from 100 points. It removes points when it finds risky patterns.

Short passwords lose points because they are easier to guess.

Common words lose points because attackers often try them first.

Keyboard patterns lose points because they are easy to predict.

Simple sequences lose points because they reduce randomness.

Repeated characters lose points because they make the password weaker.

Missing character variety loses points because the search space is smaller.

Low entropy loses points because the password is easier to guess.

Personal context loses points because names, dates, cities, and employers can be used in targeted attacks.

## Rating levels

* 85 to 100: strong
* 65 to 84: moderate
* 40 to 64: weak
* 0 to 39: critical

## Main functions

### estimate_entropy(password)

Estimates password entropy using the password length and character set size.

### contains_sequence(password)

Checks for simple letter and number sequences.

### analyze_password(password, context_terms)

Runs the full password check and returns the score, rating, findings, and recommendations.

### format_report(password, report)

Formats the result for the terminal and masks most of the password.

## Tests I used while checking it

```powershell
python password_analyzer.py --password "password123"
python password_analyzer.py --password "Qwerty2026!"
python password_analyzer.py --password "BlueRiverLaptop91!"
python password_analyzer.py --password "CorrectHorseBatteryStaple2026!"
```

Context test:

```powershell
python password_analyzer.py --password "ShimonOslo2026!" --context "Shimon,Oslo,2026"
```

## What I learned

While working on this project, I practiced:

* Python command line arguments
* regular expressions
* basic entropy calculation
* password risk scoring
* safe handling of sensitive input
* writing clear security recommendations

## Limitations

This tool gives a practical risk estimate. It cannot prove that a password is completely safe.

A password can still be unsafe if it was leaked before, reused on other websites, stored badly, or shared with someone else.

The current version does not check online breach databases. I kept it local for privacy and simplicity.

## Future improvements

* Add an optional Have I Been Pwned check using the safe k anonymity method
* Add a small web page version
* Add more test cases
* Add company password policy checks
* Export reports to JSON or CSV
* Add a simple chart for score comparison

