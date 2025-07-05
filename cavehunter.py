#!/usr/bin/env python3
import pefile
import os
import argparse

# Flag di sezione
IMAGE_SCN_MEM_EXECUTE = 0x20000000  # eseguibile
IMAGE_SCN_CNT_CODE = 0x00000020  # contiene codice
IMAGE_SCN_MEM_READ = 0x40000000  # leggibile
IMAGE_SCN_MEM_WRITE = 0x80000000  # scrivibile

BANNER = r"""
_________                      ___ ___               __                
\_   ___ \_____ ___  __ ____  /   |   \ __ __  _____/  |_  ___________ 
/    \  \/\__  \\  \/ // __ \/    ~    \  |  \/    \   __\/ __ \_  __ \
\     \____/ __ \\   /\  ___/\    Y    /  |  /   |  \  | \  ___/|  | \/
 \______  (____  /\_/  \___  >\___|_  /|____/|___|  /__|  \___  >__|   
        \/     \/          \/       \/            \/          \/       
"""


def find_code_caves(pe, min_cave_size, fillers, exec_only=False, code_only=False, rx_only=False):
    """
    Trova sequence di byte nulli (code caves) in un file PE.

    :param pe: oggetto pefile.PE
    :param min_cave_size: dimensione minima del cave in byte
    :param fillers: lista di byte (int) da considerare come filler
    :param exec_only: filtra solo sezioni eseguibili
    :param code_only: filtra solo sezioni con IMAGE_SCN_CNT_CODE
    :param rx_only: filtra solo sezioni leggibili+eseguibili
    :return: lista di dizionari con dettagli di ciascun cave
    """
    caves = []
    for section in pe.sections:
        # Nome sezione senza null terminator
        name = section.Name.rstrip(b'\x00').decode('ascii', errors='ignore')
        char = section.Characteristics
        is_exec = bool(char & IMAGE_SCN_MEM_EXECUTE)
        is_code = bool(char & IMAGE_SCN_CNT_CODE)
        is_read = bool(char & IMAGE_SCN_MEM_READ)

        # Applicazione filtri
        if exec_only and not is_exec:
            continue
        if code_only and not is_code:
            continue
        if rx_only and not (is_read and is_exec):
            continue

        # Estrazione dati raw basata su SizeOfRawData
        raw_start = section.PointerToRawData
        raw_size = section.SizeOfRawData
        raw_data = pe.__data__[raw_start:raw_start + raw_size]

        # Calcolo entropia della sezione
        entropy = section.get_entropy()

        idx = 0
        length = len(raw_data)
        while idx < length:
            if raw_data[idx] in fillers:
                run_start = idx
                filler_byte = raw_data[idx]
                while idx < length and raw_data[idx] == filler_byte:
                    idx += 1
                run_len = idx - run_start
                if run_len >= min_cave_size:
                    va = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress + run_start
                    fo = section.PointerToRawData + run_start
                    caves.append({
                        'section': name,
                        'size': run_len,
                        'entropy': round(entropy, 2),
                        'va': hex(va),
                        'offset': hex(fo),
                        'exec': is_exec,
                        'filler': filler_byte
                    })
            else:
                idx += 1
    return caves


def print_caves(caves, fillers):
    """
    Stampa in output i code caves trovati, con entropia colorata da verde a rosso,
    i byte di filler usati complessivamente e per ogni cave.
    """
    print(f"[*] Byte di filler usati: {', '.join(f'{b:02X}' for b in fillers)}")
    if not caves:
        print("[-] Nessun code cave trovato.")
        return
    print(f"[+] Trovati {len(caves)} code cave:\n")
    for cave in caves:
        badge = "[EXEC]" if cave['exec'] else "[DATA]"
        # Calcolo colore dell'entropia (gradient RGB da verde a rosso)
        p = min(max(cave['entropy'] / 8.0, 0.0), 1.0)
        r = int(p * 255)
        g = int((1 - p) * 255)
        color = f"\033[38;2;{r};{g};0m"
        reset = "\033[0m"
        ent_str = f"{color}{cave['entropy']:.2f}{reset}"
        filler_str = f"{cave['filler']:02X}"
        print(
            f"{badge} Sezione: {cave['section']:<8} | "
            f"Size: {cave['size']:>4} byte | "
            f"Filler: {filler_str} | "
            f"Entropia: {ent_str} | "
            f"VA: {cave['va']} | Offset: {cave['offset']}"
        )


def main():
    parser = argparse.ArgumentParser(
        description="CodeCaveFinder – Trova code caves in un file PE"
    )
    parser.add_argument(
        "file", help="Percorso del file PE da analizzare"
    )
    parser.add_argument(
        "-m", "--min-size", type=int, default=300,
        help="Dimensione minima del code cave in byte (default: 300)"
    )
    parser.add_argument(
        "--fillers", type=str, default="00,CC,90",
        help="Byte di filler da cercare, separati da virgola in esadecimale (default: 00,CC,90)"
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-e", "--exec-only", action="store_true",
        help="Mostra solo sezioni eseguibili"
    )
    group.add_argument(
        "--code-only", action="store_true",
        help="Mostra solo sezioni con IMAGE_SCN_CNT_CODE"
    )
    group.add_argument(
        "--rx-only", action="store_true",
        help="Mostra solo sezioni leggibili+eseguibili"
    )
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        parser.error(f"File non trovato: {args.file}")
    if args.min_size <= 0:
        parser.error("La dimensione minima deve essere maggiore di zero.")

    try:
        fillers = [int(b, 16) for b in args.fillers.split(',') if b]
    except ValueError:
        parser.error("Formato dei fillers non valido. Usa esadecimale separato da virgola.")

    print(f"[*] Analisi del file: {args.file}")
    print(f"[*] Dimensione minima dei code cave: {args.min_size} byte")
    mode = (
        "exec-only" if args.exec_only else
        "code-only" if args.code_only else
        "rx-only" if args.rx_only else
        "tutte le sezioni"
    )
    print(f"[*] Modalità: {mode}\n")

    try:
        pe = pefile.PE(args.file)
    except pefile.PEFormatError as e:
        print(f"[-] Errore: file non valido PE ({e})")
        return

    caves = find_code_caves(
        pe,
        args.min_size,
        fillers,
        exec_only=args.exec_only,
        code_only=args.code_only,
        rx_only=args.rx_only
    )
    print_caves(caves, fillers)


if __name__ == "__main__":
    print(BANNER)
    main()
