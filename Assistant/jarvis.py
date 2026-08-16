import ollama
import pyttsx3
import os
import webbrowser

# --- JARVIS VOICE ---
engine = pyttsx3.init()
def speak(text):
    print(f"Jarvis: {text}")
    engine.say(text)
    engine.runAndWait()

# --- JARVIS SYSTEM BRAIN ---
def jarvis_brain(user_input):
    try:
        # Aapka local llama3 model use ho raha hai
        response = ollama.chat(model='llama3', messages=[
            {'role': 'system', 'content': 'Tumhara naam Jarvis hai. Tum Uzan Khan ke personal assistant ho. Tum ek expert hacker aur data engineer ki tarah baat karte ho. Roman Urdu use karo.'},
            {'role': 'user', 'content': user_input},
        ])
        return response['message']['content']
    except Exception as e:
        return f"Boss, brain mein error hai: {str(e)}"

def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    speak("Jarvis is online and fully local. No internet needed for thinking.")

    while True:
        boss_msg = input("\n[Boss Uzan]: ").lower()

        if boss_msg in ["exit", "stop", "bye"]:
            speak("Systems going offline. Allah Hafiz Boss.")
            break

        # --- HANDS (System Actions) ---
        if "open" in boss_msg:
            site = boss_msg.replace("open", "").strip()
            speak(f"Opening {site}...")
            webbrowser.open(f"https://{site}.com")
            
        elif "create file" in boss_msg:
            with open("jarvis_log.txt", "w") as f:
                f.write("Jarvis System File.")
            speak("File created successfully.")

        # --- MIND (Intelligence) ---
        else:
            print("[Jarvis is Thinking...]")
            reply = jarvis_brain(boss_msg)
            speak(reply)

if __name__ == "__main__":
    main()