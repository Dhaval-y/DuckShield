import keyboard

def on_key(event):
    print(event.name)

keyboard.on_press(on_key)

print("Listening...")
keyboard.wait("esc")