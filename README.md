````markdown
_________                      ___ ___               __                
\_   ___ \_____ ___  __ ____  /   |   \ __ __  _____/  |_  ___________ 
/    \  \/\__  \\  \/ // __ \/    ~    \  |  \/    \   __\/ __ \_  __ \
\     \____/ __ \\   /\  ___/\    Y    /  |  /   |  \  | \  ___/|  | \/
 \______  (____  /\_/  \___  >\___|_  /|____/|___|  /__|  \___  >__|   
        \/     \/          \/       \/            \/          \/     
By Mario Protopapa alias DeBuG
````
# 🕵️‍♂️ Cave Hunter – CodeCaveFinder README (Full Guide)

> Cave Hunter is a Python script built for security researchers, ethical hackers, and red team operators. It analyzes PE (Portable Executable) files to identify unused memory regions — known as **code caves** — where custom shellcode or payloads can be injected and executed stealthily, avoiding many static and dynamic detection techniques.

---

## 📌 Tool Purpose

**Cave Hunter** is designed to:

* ✅ Detect **code caves** in PE files (.exe, .dll) — contiguous sequences of null bytes (`0x00`) of configurable length.
* ✅ Identify suitable sections for injecting **shellcode, loaders, or backdoors**.
* ✅ Provide detailed insights, including:

  * Section name
  * Cave size
  * Section entropy (used to evaluate data randomness)
  * Virtual address (VA) and file offset
  * Executability flag

---

## 🔬 Why Code Caves?

In **post-exploitation**, **persistence**, or **evasion** scenarios, code caves offer strategic benefits:

* **Stealth**: No new section added = fewer AV/EDR alerts.
* **Compatibility**: Caves already exist in mapped memory, reducing footprint.
* **Direct Execution**: Virtual addresses can be used directly to jump to payloads.
* **Entropy Control**: Low-entropy areas are optimal for storing clear or compressed code without corruption.

---

## 🛠️ Requirements

* **Python**: 3.6 or higher
* **Dependencies**:

  ```bash
  pip install pefile
  ```

---

## ⚙️ Installation

1. **Clone the repository**

   ```bash
   git clone https://github.com/your-username/cavehunter.git
   cd cave-hunter
   ```

2. **Install the dependency**

   ```bash
   pip install pefile
   ```

3. **(Optional) Make script executable**

   ```bash
   chmod +x cavehunter.py
   ```

---

## 🚀 Usage

```bash
./cavehunter.py [OPTIONS] <PE_file_path>
```

| Option              | Description                                    |
| ------------------- | ---------------------------------------------- |
| `-m`, `--min-size`  | Minimum cave size in bytes (default: `300`)    |
| `-e`, `--exec-only` | Scan only executable sections                  |
| `--code-only`       | Scan only sections with `IMAGE_SCN_CNT_CODE`   |
| `--rx-only`         | Scan only readable **and** executable sections |
| `-h`, `--help`      | Show usage and exit                            |

---

## 🧪 Example Commands

* **Basic scan** (≥300 bytes in all sections):

  ```bash
  ./cavehunter.py sample.exe
  ```

* **Executable sections only**, caves ≥ 500 bytes:

  ```bash
  ./cavehunter.py -e -m 500 target.dll
  ```

* **Code-only sections**:

  ```bash
  ./cavehunter.py --code-only mypayload.exe
  ```

* **Read+execute sections only**:

  ```bash
  ./codecavefinder.py --rx-only agent.exe
  ```

---

## 🔎 Internal Mechanics

### 1. **PE Parsing**

`pefile` reads PE headers and section tables, extracting names, sizes, flags, and memory layout.

### 2. **Section Filtering**

Based on flags like `--exec-only`, `--code-only`, and `--rx-only`, sections are included if they match:

* Executable (`IMAGE_SCN_MEM_EXECUTE`)
* Contains code (`IMAGE_SCN_CNT_CODE`)
* Readable (`IMAGE_SCN_MEM_READ`)

### 3. **Null Byte Scanning**

For each section:

* Raw data is scanned byte-by-byte.
* On detecting a `0x00` run, the script measures its length.
* If the sequence is ≥ `--min-size`, it's reported as a cave.

### 4. **Entropy Measurement**

Each section's entropy is calculated using `get_entropy()`:

* Helps detect encrypted or compressed sections.
* Lower entropy caves are more suitable for code injection.

### 5. **Color-Coded Output**

Each found code cave includes:

* `[EXEC]` or `[DATA]` badge
* Section name (e.g. `.text`, `.data`)
* Cave size in bytes
* Color-coded entropy: green (low) to red (high)
* Virtual Address (VA) and file offset (hex)

---

## 🧠 Red Team Scenarios

### 🛠️ Post-Exploitation / Payload Staging

* Insert shellcode, stagers, or loader routines in unused areas.
* Use jumps or function hooks to redirect execution to the cave.

### 🔐 Persistence

* Embed persistent logic in legit binaries.
* Restore original flow post-payload (PUSHAD/POPAD techniques).
* Optional: update PE checksums to maintain stealth.

### 🛡️ Evasion

* Avoid creating new sections that raise AV flags.
* Reuse legitimate mapped memory.
* Hide in low entropy, unmonitored zones.

---

## 🤝 Contributing

1. Fork this repo
2. Create a new branch:

   ```bash
   git checkout -b feature/NewFeature
   ```
3. Commit your changes:

   ```bash
   git commit -am "Added new capability"
   ```
4. Push and open a Pull Request describing your enhancement

---

## 📄 License

This project is licensed under the **MIT License**.
You are free to use, modify, and distribute it.
See `LICENSE` for more information.

