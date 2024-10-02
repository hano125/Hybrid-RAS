import os
import tkinter as tk
from tkinter import filedialog, messagebox
import time
from encryption import generate_rsa_keys, encrypt_aes, encrypt_rsa
from decryption import decrypt_aes, decrypt_rsa

class HybridEncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Hybrid Encryption")
        
        # Generate RSA keys
        self.private_key, self.public_key = generate_rsa_keys()
        
        # Initialize storage for encrypted data and keys
        self.encrypted_data = None
        self.encrypted_key = None
        
        # Lists to store times
        self.encryption_times = []
        self.decryption_times = []
        
        # Create GUI components
        self.create_widgets()
        
    def create_widgets(self):
        # Section for encrypting text input
        self.text_label = tk.Label(self.root, text="Input Text:")
        self.text_label.pack()
        self.text_area = tk.Text(self.root, height=10, width=50)  # Changed to Text widget
        self.text_area.pack()
        self.encrypt_text_button = tk.Button(self.root, text="Encrypt Text", command=self.encrypt_text)
        self.encrypt_text_button.pack()
        
        # Section for encrypting multimedia files
        self.file_label = tk.Label(self.root, text="Select Multimedia File:")
        self.file_label.pack()
        self.file_button = tk.Button(self.root, text="Browse", command=self.browse_file)
        self.file_button.pack()
        self.encrypt_file_button = tk.Button(self.root, text="Encrypt File", command=self.encrypt_file)
        self.encrypt_file_button.pack()

        # Section for real-time news input
        self.news_label = tk.Label(self.root, text="Input News Data:")
        self.news_label.pack()
        self.news_text = tk.Text(self.root, height=10, width=50)
        self.news_text.pack()
        self.encrypt_news_button = tk.Button(self.root, text="Encrypt News", command=self.encrypt_news)
        self.encrypt_news_button.pack()
        
        # Decrypt button
        self.decrypt_button = tk.Button(self.root, text="Decrypt", command=self.decrypt_data)
        self.decrypt_button.pack()
        
        # Time table
        self.time_label = tk.Label(self.root, text="Encryption/Decryption Times (in seconds):")
        self.time_label.pack()
        self.time_table = tk.Text(self.root, height=10, width=50)
        self.time_table.pack()

    def browse_file(self):
        filename = filedialog.askopenfilename()
        self.file_label.config(text=filename)

    def encrypt_text(self):
        # Get text from text area
        plaintext = self.text_area.get("1.0", tk.END).strip().encode()  # Get all text from the Text widget
        self._encrypt_data(plaintext)

    def encrypt_file(self):
        file_path = self.file_label.cget("text")
        if file_path:
            with open(file_path, 'rb') as file:
                file_data = file.read()
                self._encrypt_data(file_data)
        else:
            messagebox.showerror("Error", "Please select a multimedia file to encrypt.")

    def encrypt_news(self):
        news_data = self.news_text.get("1.0", tk.END).strip().encode()
        self._encrypt_data(news_data)

    def _encrypt_data(self, data):
        if not data:
            messagebox.showerror("Error", "No data to encrypt.")
            return
        
        # Generate AES key
        aes_key = os.urandom(32)  # AES-256
        start_time = time.perf_counter()  # Use time.perf_counter() for better accuracy
        
        # Encrypt data
        self.encrypted_data = encrypt_aes(aes_key, data)
        self.encrypted_key = encrypt_rsa(self.public_key, aes_key)  # Encrypt the AES key with RSA
        end_time = time.perf_counter()

        # Log times
        self.encryption_times.append(end_time - start_time)
        self.update_time_log("Encryption", end_time - start_time)

        # Display success message
        messagebox.showinfo("Success", "Data Encrypted Successfully!")

    def decrypt_data(self):
        if not self.encrypted_data or not self.encrypted_key:
            messagebox.showerror("Error", "No data to decrypt. Please encrypt first.")
            return
        
        try:
            start_time = time.perf_counter()  # Use time.perf_counter() for better accuracy
            
            # Decrypt the AES key with RSA
            aes_key = decrypt_rsa(self.private_key, self.encrypted_key)
            
            # Decrypt the data
            decrypted_data = decrypt_aes(aes_key, self.encrypted_data)
            end_time = time.perf_counter()

            # Log times
            self.decryption_times.append(end_time - start_time)
            self.update_time_log("Decryption", end_time - start_time)

            # Save or display decrypted data
            with open("decrypted_output.txt", 'wb') as file:  # Save decrypted data to a file
                file.write(decrypted_data)
            
            messagebox.showinfo("Success", "Data Decrypted Successfully! Output saved to 'decrypted_output.txt'.")
        except Exception as e:
            messagebox.showerror("Decryption Error", f"An error occurred during decryption: {str(e)}")

    def update_time_log(self, operation, elapsed_time):
        self.time_table.insert(tk.END, f"{operation}: {elapsed_time:.5f} seconds\n")
        # Display the average time if more than one time is recorded
        if operation == "Encryption" and len(self.encryption_times) > 1:
            avg_time = sum(self.encryption_times) / len(self.encryption_times)
            self.time_table.insert(tk.END, f"Average Encryption Time: {avg_time:.5f} seconds\n")
        elif operation == "Decryption" and len(self.decryption_times) > 1:
            avg_time = sum(self.decryption_times) / len(self.decryption_times)
            self.time_table.insert(tk.END, f"Average Decryption Time: {avg_time:.5f} seconds\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = HybridEncryptionApp(root)
    root.mainloop()
