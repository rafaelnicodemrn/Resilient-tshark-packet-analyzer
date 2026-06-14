import subprocess
import os
import sys
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s | [%(levelname)s] | %(message)s')

def iniciar_captura():
    # Parametrização via variáveis locais (facilmente alteráveis por variáveis de ambiente)
    INTERFACE = os.getenv("MONITOR_INTERFACE", "Ethernet")
    FILTRO_BPF = os.getenv("MONITOR_FILTER", "tcp port 2001 or tcp port 3050")
    PASTA_DESTINO = os.getenv("MONITOR_OUTPUT_DIR", r"C:\Capturas_Rede")
    TSHARK_CMD = os.getenv("TSHARK_PATH", "tshark")
    DURATION_SECONDS = "3600" # 1 Hora

    if not os.path.exists(PASTA_DESTINO):
        os.makedirs(PASTA_DESTINO)

    logging.info("===========================================================")
    logging.info("   INICIANDO CAPTURA CONTÍNUA DE REDE (PCAPNG)")
    logging.info("   Pressione Ctrl+C para encerrar o monitoramento.")
    logging.info("===========================================================")

    while True:
        agora = datetime.now()
        nome_arquivo = agora.strftime("Captura_%d-%m-%Y_%H-%M-%S.pcapng")
        caminho_completo = os.path.join(PASTA_DESTINO, nome_arquivo)
        
        logging.info(f"Gravando tráfego no buffer estável: {nome_arquivo}")
        
        comando = [
            TSHARK_CMD, "-i", INTERFACE, "-f", FILTRO_BPF,
            "-a", f"duration:{DURATION_SECONDS}", "-w", caminho_completo
        ]
        
        try:
            subprocess.run(comando, check=True)
        except FileNotFoundError:
            logging.error("O executável 'tshark' não foi localizado no PATH do sistema.")
            sys.exit(1)
        except KeyboardInterrupt:
            logging.info("Captura encerrada de forma controlada pelo usuário.")
            break
        except Exception as e:
            logging.error(f"Falha na execução do processo de captura: {str(e)}")

if __name__ == "__main__":
    iniciar_captura()