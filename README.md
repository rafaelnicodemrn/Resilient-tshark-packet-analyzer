# 🦈 Resilient TShark Packet Analyzer

![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python&logoColor=white)
![TShark](https://img.shields.io/badge/Wireshark-TShark-1679A7?logo=wireshark&logoColor=white)
![Dependências](https://img.shields.io/badge/depend%C3%AAncias-apenas%20stdlib-success)
![Plataforma](https://img.shields.io/badge/Windows%20%7C%20Linux-lightgrey)

Captura contínua de tráfego de rede e análise de degradação de performance client-side, com **consumo de memória constante**, usando apenas a biblioteca padrão do Python e o binário do TShark.

## ✨ Destaques

- **Leitura em stream, memória O(1):** o `.pcapng` nunca é carregado inteiro na RAM. O TShark escreve linha a linha em um pipe (`subprocess.Popen`) e o analisador processa cada pacote na hora.
- **Captura rotativa:** um arquivo novo a cada hora (`Captura_DD-MM-AAAA_HH-MM-SS.pcapng`), com filtro BPF para gravar só o tráfego que interessa.
- **Configuração por variáveis de ambiente**, sem editar código.
- **Zero dependências Python:** só `subprocess`, `glob` e `logging`.

## 🔎 Falhas detectadas

| Modo de falha | O que indica | Como é detectado |
|---|---|---|
| Silêncio estatístico / lentidão | Atraso anômalo entre pacotes | Delta entre `frame.time_epoch` acima do limite |
| Queda forçada | Conexão abortada no socket | Flag `tcp.flags.reset` |
| Zero Window | Exaustão do buffer de recepção no destino | `tcp.window_size_value = 0` |
| Retransmissão | Degradação física ou lógica da rede | `tcp.analysis.retransmission` |

## 📁 Estrutura

```
src/
├── capturador.py   # captura contínua com rotação horária
└── analisador.py   # análise em stream e geração de Relatorio_Analise.txt
```

## 🚀 Como usar

**Pré-requisito:** [Wireshark/TShark](https://www.wireshark.org/download.html) instalado.

```bash
# 1. Capturar (Ctrl+C encerra)
python src/capturador.py

# 2. Analisar os arquivos gerados
python src/analisador.py
```

### Variáveis de ambiente

| Variável | Padrão | Usada em | Descrição |
|---|---|---|---|
| `MONITOR_INTERFACE` | `Ethernet` | capturador | Interface de rede a capturar |
| `MONITOR_FILTER` | `tcp port 2001 or tcp port 3050` | capturador | Filtro BPF de captura |
| `MONITOR_OUTPUT_DIR` | `C:\Capturas_Rede` | capturador | Pasta onde os `.pcapng` são gravados |
| `TSHARK_PATH` | `tshark` | capturador | Caminho do executável do TShark |
| `MONITOR_INPUT_DIR` | `C:\Capturas_Rede` | analisador | Pasta lida pelo analisador |
| `MONITOR_LENTIDAO_THRESHOLD` | `10.0` | analisador | Limite (s) para considerar lentidão |

O relatório é gravado em `Relatorio_Analise.txt` dentro da pasta de entrada.

> O analisador espera o TShark em `C:\Program Files\Wireshark\tshark.exe` (caminho fixo no código).
