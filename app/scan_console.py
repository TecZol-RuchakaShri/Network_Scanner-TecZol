import tkinter as tk
from tkinter import scrolledtext

class ScanConsole(tk.Toplevel):
    def __init__(self, parent, title):
        super().__init__(parent)
        self.title(title)
        self.geometry("600x400")
        self.resizable(True, True)
        self.protocol("WM_DELETE_WINDOW", self.close)
        self.create_widgets()

    def create_widgets(self):
        self.console = scrolledtext.ScrolledText(self, wrap=tk.WORD, bg="white", fg="black", font=("Consolas", 10))
        self.console.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)
        self.console.config(state=tk.DISABLED) # make the text area read-only


    def append_message(self, message):
        self.console.config(state=tk.NORMAL) # make it mutable for writing data.
        self.console.insert(tk.END, message + "\n")
        self.console.config(state=tk.DISABLED) # make it immutable.
        self.console.see(tk.END)
        self.update()

    def close(self):
        self.destroy()

    def clear_console(self):
      self.console.config(state = tk.NORMAL)
      self.console.delete(1.0, tk.END)
      self.console.config(state = tk.DISABLED)


if __name__ == '__main__':
    root = tk.Tk()
    console = ScanConsole(root, "Test Console")
    console.append_message("This is a test message.")
    console.append_message("Another test message.")
    root.mainloop()