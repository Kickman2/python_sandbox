import asyncio
import tkinter as tk
from tkinter import ttk
import websockets

async def send_message(websocket):
    while True:
        message = input_text.get()
        if message.lower() == 'exit':
            await websocket.close()
            break
        await websocket.send(message)
        input_text.set("")  # Clear the input field after sending a message

async def receive_messages(websocket):
    while True:
        try:
            message = await websocket.recv()
            chat_text.insert(tk.END, f"Received: {message}\n")
        except websockets.exceptions.ConnectionClosedError:
            chat_text.insert(tk.END, "Connection closed by server.\n")
            break

async def main():
    async with websockets.connect("ws://localhost:8765") as websocket:
        asyncio.create_task(send_message(websocket))
        await receive_messages(websocket)

# Create the main window
root = tk.Tk()
root.title("Chat Client")

# Create and configure the chat text box
chat_text = tk.Text(root, wrap=tk.WORD, state=tk.DISABLED)
chat_text.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
chat_text.config(state=tk.NORMAL)

# Create a scrollbar for the chat text box
scrollbar = ttk.Scrollbar(root, command=chat_text.yview)
scrollbar.grid(row=0, column=1, sticky="ns")
chat_text.config(yscrollcommand=scrollbar.set)

# Create and configure the input field
input_text = tk.StringVar()
input_field = ttk.Entry(root, textvariable=input_text)
input_field.grid(row=1, column=0, padx=10, pady=10, sticky="ew")

# Create a button to send messages
send_button = ttk.Button(root, text="Send", command=lambda: asyncio.create_task(send_message(websocket)))
send_button.grid(row=1, column=1, padx=10, pady=10)

root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)

if __name__ == "__main__":
    asyncio.run(main())
    root.mainloop()
