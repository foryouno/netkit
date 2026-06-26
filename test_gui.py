import tkinter as tk
from tkinter import ttk

root = tk.Tk()
root.title('Test')
root.geometry('400x300')

notebook = ttk.Notebook(root)
notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

frame1 = ttk.Frame(notebook)
notebook.add(frame1, text='Tab 1')
ttk.Label(frame1, text='Hello World').pack(pady=20)

frame2 = ttk.Frame(notebook)
notebook.add(frame2, text='Tab 2')
ttk.Label(frame2, text='Tab 2 Content').pack(pady=20)

print('Window created successfully')
root.mainloop()
