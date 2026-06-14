import os
import sys
import glob
import logging
import subprocess
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s | [%(levelname)s] | %(message)s')

def executar_analise_fluxo():
    PASTA_ARQUIVOS = os.getenv("MONITOR_INPUT_DIR", r"C:\Capturas_Rede")
    LIMITE_LENTIDAO = float(os.getenv("MONITOR_LENTIDAO_THRESHOLD", "10.0"))
    TSHARK_CMD = r"C:\Program Files\Wireshark\tshark.exe"
    
    arquivos_pcap = glob.glob(os.path.join(PASTA_ARQUIVOS, "*.pcapng"))
    if not arquivos_pcap:
        logging.warning(f"Nenhum artefato .pcapng localizado no diretório: {PASTA_ARQUIVOS}")
        sys.exit(0)

    relatorio_path = os.path.join(PASTA_ARQUIVOS, "Relatorio_Analise.txt")
    with open(relatorio_path, "a", encoding="utf-8") as log_file:
        for arquivo in arquivos_pcap:
            nome_base = os.path.basename(arquivo)
            tamanho_kb = os.path.getsize(arquivo) / 1024
            
            if tamanho_kb < 10:
                continue
                
            try:
                comando = [
                    TSHARK_CMD, "-r", arquivo, "-Y", "tcp", "-T", "fields",
                    "-e", "frame.time_epoch", "-e", "ip.src", "-e", "tcp.flags.reset",
                    "-e", "tcp.window_size_value", "-e", "tcp.analysis.retransmission",
                    "-E", "separator=|"
                ]
                
                # Leitura em modo Stream (O(1) em RAM)
                processo = subprocess.Popen(comando, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
                
                tempo_anterior_epoch = None
                pacotes_lidos = 0
                alertas_lentidao = 0
                alertas_rst = 0
                alertas_zero_window = 0
                alertas_retransmissao = 0
                
                for linha in proceso.stdout:
                    linha = linha.strip()
                    if not linha: 
                        continue
                    
                    pacotes_lidos += 1
                    partes = linha.split("|")
                    if len(partes) < 4: 
                        continue
                    
                    try:
                        tempo_atual_epoch = float(partes[0])
                        ip_origem = partes[1]
                        rst_flag = partes[2]
                        window_size = partes[3]
                        retransmissao = partes[4] if len(partes) > 4 else ""
                        
                        tempo_atual_str = datetime.fromtimestamp(tempo_atual_epoch).strftime('%H:%M:%S')
                        
                        if tempo_anterior_epoch is not None:
                            delta = tempo_atual_epoch - tempo_anterior_epoch
                            if delta >= LIMITE_LENTIDAO:
                                alertas_lentidao += 1
                                tempo_ant_str = datetime.fromtimestamp(tempo_anterior_epoch).strftime('%H:%M:%S')
                                msg = f"\n  [!] LENTIDÃO: Intervalo de {delta:.2f}s entre {tempo_ant_str} e {tempo_atual_str}"
                                print(msg, end="")
                                log_file.write(f"\n[{nome_base}] {msg}")
                        else:
                            delta = 0
                                
                        if rst_flag == '1':
                            alertas_rst += 1
                            msg = f"\n  [!] QUEDA (RST): Conexão abortada por {ip_origem} às {tempo_atual_str}"
                            print(msg, end="")
                            log_file.write(f"\n[{nome_base}] {msg}")

                        if window_size == '0':
                            alertas_zero_window += 1
                            msg = f"\n  [!] GARGALO (Zero Window): Buffer cheio em {ip_origem} às {tempo_atual_str}"
                            print(msg, end="")
                            log_file.write(f"\n[{nome_base}] {msg}")
                            
                        if retransmissao != "" and tempo_anterior_epoch is not None and delta > 0.01:
                            alertas_retransmissao += 1

                        tempo_anterior_epoch = tempo_atual_epoch
                        
                    except ValueError:
                        continue
                
                processo.stdout.close()
                processo.wait()
                
                logging.info(f"Arquivo {nome_base} processado. Registros TCP analisados: {pacotes_lidos}")
                
            except Exception as e:
                logging.error(f"Falha operacional no processamento de {nome_base}: {str(e)}")

if __name__ == "__main__":
    executar_analise_fluxo()