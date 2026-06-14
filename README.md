# Resilient TShark Packet Analyzer

Ecosystem corporativo de alta performance projetado para automação de capturas contínuas de rede e análise de degradação de performance client-side com baixo consumo de memória RAM.

## Engenharia e Diferenciais de Arquitetura

* **Stream Parsing com Complexidade de Memória $O(1)$**: Ao contrário de abordagens tradicionais que carregam buffers binários massivos (.pcapng) inteiramente para a memória RAM, o motor desacopla a leitura por meio de um pipe estruturado linha a linha via `subprocess.Popen` e filtros nativos do TShark.
* **Mapeamento de 4 Modos Críticos de Falha**:
  1. *Silêncio Estatístico / Lentidão*: Captura de deltas de tempo anômalos entre pacotes.
  2. *Quedas Forçadas (TCP RST)*: Rastreabilidade instantânea de conexões abortadas em nível de socket.
  3. *Gargalos de Buffer (Zero Window)*: Identificação de exaustão de janelas de recepção no destino.
  4. *Retransmissões*: Telemetria de degradação física ou lógica de pacotes trafegados.

## Requisitos de Infraestrutura

* Wireshark / TShark instalado e mapeado no PATH do sistema operacional Windows/Linux.
