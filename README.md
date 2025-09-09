# DM Encrypter — Simple Mode

A super easy tool to encrypt and decrypt messages before sharing them on Discord (or any chat app).  
No programming knowledge needed. Just copy, paste, click one button.  
disclaimer - made for friends and very casually its probably a terrible app and flags like all antivirus since its an exe file with no safety
if you download a file under this name that isnt from this link its probably got a virus on it so dont, matter of fact dont even download this one
I couldve accidentally made a cryptominer or some shit.

---

## How to Run

1. Unzip the folder we sent you (`DM Encrypter.zip`).
   
2. Open the folder and double-click:
   
*(If Windows asks about permissions or SmartScreen, click **More info → Run anyway**. The app is safe.)*

3. The program will open with one big text box and a few buttons.

---

## How to Use

1. **Set up passphrase (one-time per friend):**
   - At the top, type a **Contact name** (e.g. `Alice`).
   - Enter a **Passphrase** (secret word/phrase you and your friend agreed on).
   - Click **Save** so you don’t have to type it again.

2. **Encrypt a message (send to friend):**
   - Type or paste your normal message into the big box.
   - Click **Do the Right Thing**.  
   - The result (a long string starting with `enc:v1:`) appears in the Result box **and is auto-copied to your clipboard**.
   - Paste that into Discord DM.

3. **Decrypt a message (received from friend):**
   - Copy the ciphertext you got from Discord (starts with `enc:v1:`).
   - Paste it into the big box.
   - Click **Do the Right Thing**.
   - The original message appears in the Result box **and is auto-copied to your clipboard**.

4. **Clipboard helpers:**
   - *Use Clipboard*: quickly load whatever you’ve copied into the big box.
   - *Copy Result*: copy the Result box manually (if you didn’t rely on auto-copy).

---

## Notes

- Both you and your friend must use the **same passphrase** for a conversation.
- Each message looks different when encrypted, even if the text is the same — this is normal and secure.
- Passphrases are saved locally in a file called `keybook.json` (never shared).
- Nothing goes through Discord bots or servers. All encryption happens **on your computer**.

---

## Troubleshooting

- If Windows warns “Unknown Publisher,” click **More info → Run anyway**.
- If the app won’t start, make sure you extracted the **entire folder** (`DM Encrypter/`) and are not running the exe from inside the zip.
- If you delete `keybook.json`, saved passphrases will be forgotten.

---

## Folder Contents
DM Encrypter.exe ← the program you run
python39.dll ← required runtime
cryptography/... ← crypto library files
pyperclip/... ← clipboard helper
keybook.json ← created after first run (stores your passphrases)

## Download (Windows)
[Get the latest DM Encrypter](https://github.com/RogueKnyt/RKsMessageDecoder/releases/download/v1.0.0/DM.Encrypter.zip)


