import tkinter as tk
from tkinter import messagebox, filedialog, ttk
import itertools
import string
import threading

class PasswordCrackerApp:
    def __init__(self, master):
        # Window Setup
        self.master = master
        master.title("Password Cracking Simulator")
        master.geometry("500x600")
        master.configure(bg='#f0f0f0')

        # Username Section
        username_frame = tk.Frame(master, bg='#f0f0f0')
        username_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(username_frame, text="Username:", bg='#f0f0f0').pack(side=tk.LEFT)
        self.username_entry = tk.Entry(username_frame, width=30)
        self.username_entry.pack(side=tk.LEFT, padx=10)

        # Dictionary Attack Section
        dict_frame = tk.Frame(master, bg='#f0f0f0')
        dict_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(dict_frame, text="Dictionary File:", bg='#f0f0f0').pack(side=tk.LEFT)
        self.dict_file_entry = tk.Entry(dict_frame, width=30)
        self.dict_file_entry.pack(side=tk.LEFT, padx=10)
        
        dict_browse_btn = tk.Button(dict_frame, text="Browse", command=self.browse_dictionary)
        dict_browse_btn.pack(side=tk.LEFT)

        # Brute Force Configuration
        brute_frame = tk.Frame(master, bg='#f0f0f0')
        brute_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(brute_frame, text="Character Set:", bg='#f0f0f0').pack(side=tk.LEFT)
        self.char_set_var = tk.StringVar(value="All Letters")
        char_sets = ["All Letters", "Lowercase", "Uppercase", "Alphanumeric"]
        char_set_dropdown = tk.OptionMenu(brute_frame, self.char_set_var, *char_sets)
        char_set_dropdown.pack(side=tk.LEFT, padx=10)

        tk.Label(brute_frame, text="Max Length:", bg='#f0f0f0').pack(side=tk.LEFT)
        self.max_length_var = tk.IntVar(value=5)
        max_length_spinner = tk.Spinbox(brute_frame, from_=1, to=10, 
                                         textvariable=self.max_length_var, width=5)
        max_length_spinner.pack(side=tk.LEFT, padx=10)

        # Action Buttons
        btn_frame = tk.Frame(master, bg='#f0f0f0')
        btn_frame.pack(fill=tk.X, padx=10, pady=5)
        
        dict_attack_btn = tk.Button(btn_frame, text="Dictionary Attack", 
                                    command=self.start_dictionary_attack)
        dict_attack_btn.pack(side=tk.LEFT, padx=5)
        
        brute_attack_btn = tk.Button(btn_frame, text="Brute Force Attack", 
                                     command=self.start_brute_force_attack)
        brute_attack_btn.pack(side=tk.LEFT, padx=5)

        # Progress Bar
        progress_frame = tk.Frame(master, bg='#f0f0f0')
        progress_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = tk.ttk.Progressbar(progress_frame, 
                                                variable=self.progress_var, 
                                                maximum=100, 
                                                length=400)
        self.progress_bar.pack(side=tk.TOP, pady=5)
        
        # Results Area
        result_frame = tk.Frame(master, bg='#f0f0f0')
        result_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.result_text = tk.Text(result_frame, height=10, width=60)
        self.result_text.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

    def browse_dictionary(self):
        filename = filedialog.askopenfilename(title="Select Dictionary File")
        self.dict_file_entry.delete(0, tk.END)
        self.dict_file_entry.insert(0, filename)

    def start_dictionary_attack(self):
        # Reset UI
        self.result_text.delete(1.0, tk.END)
        self.progress_var.set(0)
        
        # Get inputs
        username = self.username_entry.get()
        dict_file = self.dict_file_entry.get()
        
        # Validate inputs
        if not username or not dict_file:
            messagebox.showerror("Error", "Please enter username and select dictionary file")
            return
        
        # Start attack in a separate thread
        threading.Thread(target=self.dictionary_attack, 
                         args=(username, dict_file), 
                         daemon=True).start()

    def dictionary_attack(self, username, dict_file):
        try:
            with open(dict_file, 'r') as file:
                passwords = file.readlines()
                total = len(passwords)
                
                for i, password in enumerate(passwords):
                    password = password.strip()
                    
                    # Update progress
                    progress = (i / total) * 100
                    self.progress_var.set(progress)
                    
                    # Check login
                    if self.attempt_login(username, password):
                        self.master.after(0, self.show_result, 
                                          f"Dictionary Attack Successful!\nPassword: {password}")
                        return
            
            # If no password found
            self.master.after(0, self.show_result, "Dictionary Attack Failed. No password found.")
        
        except FileNotFoundError:
            self.master.after(0, self.show_result, f"Error: Dictionary file {dict_file} not found.")
        except Exception as e:
            self.master.after(0, self.show_result, f"Error: {str(e)}")

    def start_brute_force_attack(self):
        # Reset UI
        self.result_text.delete(1.0, tk.END)
        self.progress_var.set(0)
        
        # Get inputs
        username = self.username_entry.get()
        
        # Validate inputs
        if not username:
            messagebox.showerror("Error", "Please enter username")
            return
        
        # Start attack in a separate thread
        threading.Thread(target=self.brute_force_attack, 
                         args=(username,), 
                         daemon=True).start()

    def brute_force_attack(self, username):
        # Determine character set
        char_set_map = {
            "All Letters": string.ascii_letters,
            "Lowercase": string.ascii_lowercase,
            "Uppercase": string.ascii_uppercase,
            "Alphanumeric": string.ascii_letters + string.digits
        }
        characters = char_set_map[self.char_set_var.get()]
        max_length = self.max_length_var.get()

        # Total combinations calculation
        total_combinations = sum(len(characters)**l for l in range(1, max_length+1))
        
        # Iterate through combinations
        current_attempt = 0
        for length in range(1, max_length+1):
            for password in itertools.product(characters, repeat=length):
                password = ''.join(password)
                
                # Update progress
                current_attempt += 1
                progress = (current_attempt / total_combinations) * 100
                self.progress_var.set(min(progress, 100))
                
                # Attempt login
                if self.attempt_login(username, password):
                    self.master.after(0, self.show_result, 
                                      f"Brute Force Attack Successful!\nPassword: {password}")
                    return
        
        # If no password found
        self.master.after(0, self.show_result, "Brute Force Attack Failed. No password found.")

    def attempt_login(self, username, password):
        # Simulated login - replace with actual authentication logic
        test_username = "admin"
        test_password = "hello"
        return username == test_username and password == test_password

    def show_result(self, message):
        # Update result text and reset progress
        self.result_text.insert(tk.END, message + "\n")
        self.progress_var.set(0)

def main():
    root = tk.Tk()
    PasswordCrackerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
