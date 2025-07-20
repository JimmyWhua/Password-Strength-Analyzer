# Project: Tool to measure password strength
# Class  : CSCE 477 - Fall 2024
# Author : Cong Nguyen, Jimmy Hua

'''
This module provides functionality to:
- Check password strength using various criteria
- Generate secure random passwords
- Suggest improvements for weak passwords
- Export password check results
Supports for GUI interfaces
'''

import tkinter as tk
from tkinter import filedialog, messagebox
import re
import random
import string
import logging
import json
from functools import lru_cache

from zxcvbn import zxcvbn

logging.basicConfig(filename='password_checker.log', level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s')

'''Class to handle wordlists for password checking.'''
class Wordlist:
    _cache = {}

    def __init__(self, file_path):
        self.file_path = file_path
        self.words = self.load_wordlist()

    # Load wordlist from file.
    def load_wordlist(self):
        if self.file_path in self._cache:
            return self._cache[self.file_path]

        try:
            with open(self.file_path, 'r', encoding='utf-8') as file:
                wordlist = [line.strip() for line in file]
                self._cache[self.file_path] = wordlist
                return wordlist
        except FileNotFoundError as e:
            raise FileNotFoundError(f"Error: File '{self.file_path}' not found.") from e
        except Exception as e:
            raise RuntimeError(
                f"Error loading wordlist from '{self.file_path}': {str(e)}"
            ) from e

    # Check if a word is in the wordlist.
    def is_word_in_list(self, word):
        return word in self.words

'''Class to store password strength check results.'''
class StrengthResult:
    def __init__(self, strength: str, score: int, message: str):
        self.strength = strength
        self.score = score
        self.message = message

'''Class to handle password strength checking and related operations.'''
class PasswordStrength:
    def __init__(self, weak_wordlist_path: str = "./weak_passwords.txt",
        breached_wordlist_path: str = "./breached_passwords.txt"):
        self.weak_wordlist = (Wordlist(weak_wordlist_path)
            if weak_wordlist_path else None)
        self.breached_wordlist = (Wordlist(breached_wordlist_path)
            if breached_wordlist_path else None)
        self.min_password_length = 12
        self.strength_mapping = {
            0: "Very Weak",
            1: "Weak",
            2: "Moderate",
            3: "Strong",
            4: "Very Strong"
        }

    @lru_cache(maxsize=1000)
    # Check the strength of a given password.
    def check_password_strength(self, password: str) -> 'StrengthResult':
        
        # Early return for passwords that don't meet basic length requirements
        if not self._is_length_valid(password):
            if (len(password) == 0):
                return  StrengthResult("Empty password", 0, f"Please enter the password.")
            return StrengthResult("Invalid Length", 0, f"Password should be at least {self.min_password_length} characters long.")
        
        # Early return for weak passwords found in a wordlist
        if self._is_weak_word(password):
            return StrengthResult("Weak", 0, "Password is commonly used and easily guessable.")

        # Early return for breached passwords
        if self._is_breached_word(password):
            return StrengthResult("Not Allowed", 0, "This password is not allowed, as it is commonly found in data leaks.")
        
        # Evaluate password strength using zxcvbn
        password_strength = zxcvbn(password)
        score = password_strength["score"]
        strength = self.strength_mapping[score]

        # Check for complexity issues
        complexity_issues = self._get_complexity_issues(password)
        if complexity_issues:
            return StrengthResult("Lack Complexity", score, f"Password does not meet all requirements. \n Missing: {', '.join(complexity_issues)}.")

        # Return strong password result if all conditions are met
        if score == 4:
            return StrengthResult(strength, score, f"Password meets all the requirements. Score: {score}/4")

        # Return feedback with suggestions for improvement
        suggestions = password_strength["feedback"]["suggestions"]
        return StrengthResult(strength, score, f"Password is {strength.lower()}. Score: {score}/4. \n Suggestions: {', '.join(suggestions)}")

    # Checks if the password length meets the minimum requirement.
    def _is_length_valid(self, password: str) -> bool:
        return len(password) >= self.min_password_length

    # Checks if the password is in the weak word list.
    def _is_weak_word(self, password: str) -> bool:
        return self.weak_wordlist and self.weak_wordlist.is_word_in_list(password)

    # Checks if the password is in the banned word list.
    def _is_breached_word(self, password: str) -> bool:
        return self.breached_wordlist and self.breached_wordlist.is_word_in_list(password)

    # Checks for missing complexity requirements in the password.
    def _get_complexity_issues(self, password: str) -> list:
        issues = []
        if not re.search(r'[A-Z]', password):
            issues.append("uppercase letter")
        if not re.search(r'[a-z]', password):
            issues.append("lowercase letter")
        if not re.search(r'\d', password):
            issues.append("number")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>-_`~+=]', password):
            issues.append("special character")
        return issues

    # Generate a random password.
    def generate_random_password(self, length=16):
        characters = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choice(characters) for _ in range(length))

    # Suggest improvements for a given password.
    def suggest_improvements(self, password: str) -> str:
        result = self.check_password_strength(password)
        suggestions = []

        # Check password length using match-case
        match len(password) < self.min_password_length:
            case True:
                suggestions.append(f"Increase length to at least {self.min_password_length} characters")

        # Check for uppercase letters using match-case
        match re.search(r'[A-Z]', password) is None:
            case True:
                suggestions.append("Add uppercase letters")
        
        # Check for lowercase letters using match-case
        match re.search(r'[a-z]', password) is None:
            case True:
                suggestions.append("Add lowercase letters")
        
        # Check for digits using match-case
        match re.search(r'\d', password) is None:
            case True:
                suggestions.append("Add numbers")
        
        # Check for special characters using match-case
        match re.search(r'[!@#$%^&*(),.?":{}|<>-_`~+=]', password) is None:
            case True:
                suggestions.append("Add special characters")

        # If no suggestions were added, take suggestions from the password strength check
        if not suggestions:
            suggestions = result.message.split("No suggestions. ")[-1].split(", ")

        return "Suggested improvements:\n\n" + "\n".join(f"- {s}" for s in suggestions)

'''GUI class for Password Evaluation.'''
class PasswordStrengthGUI:
    def __init__(self, master):
        self.master = master
        master.title("Password Evaluation")

        self.password_strength = PasswordStrength()

        self.label = tk.Label(master, text="Enter password:")
        self.label.pack()

        self.password_entry = tk.Entry(master, show="*")
        self.password_entry.pack()
        self.password_entry.bind('<Return>', lambda event: self.check_password())

        hide_button = tk.Button(master, text="Hide Password", command=self.hide_password)
        hide_button.pack()

        show_button = tk.Button(master, text="Show Password", command=self.show_password)
        show_button.pack()
        
        self.check_button = tk.Button(master, text="Evaluate Strength", command=self.check_password)
        self.check_button.pack()
        self.result_label = tk.Label(master, text="")
        self.result_label.pack()

        self.suggestion_label = tk.Label(master, text="")
        self.suggestion_label.pack()

        self.generate_button = tk.Button(master, text="Auto Generating Password",
            command=self.generate_password)
        self.generate_button.pack()

        self.export_button = tk.Button(master, text="Export Results", command=self.export_results)
        self.export_button.pack()

        self.quit_button = tk.Button(master, text="Quit", command=master.quit)
        self.quit_button.pack()

        self.tip_label = tk.Label(master, text="\nTips:\n"
            "\n- Do not include any personal information in your password"
            "\n- Use a combination of uppercase and lowercase letters"
            "\n- Include numbers and special characters"
            "\n- Avoid common words or phrases"
            "\n- Use a unique password for each account",
            fg="blue", justify="left")
        self.tip_label.pack()

        # Added text box to display generated password
        self.password_display = tk.Text(master, height=2, width=30, wrap=tk.WORD)
        self.password_display.pack()

        # Added Copy to Clipboard Button
        self.copy_button = tk.Button(master, text="Copy to Clipboard", command=self.copy_password)
        self.copy_button.pack()

        self.results = []
    
    # Show password.
    def show_password(self):
        self.password_entry.config(show="")
    
    # Hidden password.
    def hide_password(self):
        self.password_entry.config(show="*")

    # Check the strength of the entered password.
    def check_password(self):
        password = self.password_entry.get()
        result = self.password_strength.check_password_strength(password)
        self.result_label.config(text=f"{result.strength}: {result.message}")
        suggestions = self.password_strength.suggest_improvements(password)
        self.suggestion_label.config(text=suggestions)
        self.results.append({"password": password, "strength": result.strength, "message": result.message})
        logging.info("Password checked: %s", result.strength)

    # Generate a random strong password.
    def generate_password(self):
        password = self.password_strength.generate_random_password()
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)
        # Insert the generated password into the text box
        self.password_display.delete(1.0, tk.END)
        self.password_display.insert(tk.END, password)
        copy_to_clipboard = messagebox.askyesno("Generated Password",
            f"Generated password: {password}\n\nDo you want to copy the password to clipboard?")
        if copy_to_clipboard:
            self.master.clipboard_clear()
            self.master.clipboard_append(password)
            messagebox.showinfo("Clipboard", "Password copied to clipboard.")

    # Copy the password from the text box to clipboard.
    def copy_password(self):
        password = self.password_display.get(1.0, tk.END).strip()
        self.master.clipboard_clear()
        self.master.clipboard_append(password)
        messagebox.showinfo("Clipboard", "Password copied to clipboard.")
    
    # Export the password check results to a JSON file.
    def export_results(self):
        if not self.results:
            messagebox.showerror("Error", "No results to export.")
            return

        # Ask the user to select a file path to save the results
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )

        if not file_path:
            return

        # Write the results to the selected file
        try:
            with open(file_path, 'w', encoding='utf-8') as file:
                json.dump(self.results, file, indent=4)
            messagebox.showinfo("Export Successful", f"Results exported to {file_path}.")
        except Exception as error:
            messagebox.showerror("Error", f"An error occurred while exporting the results: {str(error)}")

'''Main entry point for both GUI and CLI interfaces.'''
def main():
    root = tk.Tk()
    PasswordStrengthGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()