# Windows Log Parser Pro

Parser e analisador de logs com foco em investigação e detecção de eventos suspeitos.

## Melhorias desta versão

- Severidade preservada no `LogRecord` e nas exportações.
- `csv.Sniffer()` protegido contra arquivos CSV difíceis de detectar.
- `--field-map` do JSONL aceita mapas parciais sem `KeyError`.
- Regra de escalação de privilégio usa correlação temporal.
- Filtro temporal descarta registros sem timestamp quando um intervalo é solicitado.
- `dashboard_payload()` gera um contrato JSON pronto para API.
- CLI `hunt` executa cada regra de forma explícita, evitando dupla execução da regra de brute force.
- Testes automatizados incluídos.

## Dashboard

Abra `dashboard/index.html` em um servidor HTTP. Ele tenta buscar:

`GET /api/dashboard`

Se a API não existir, o frontend usa dados demonstrativos.

## Integração recomendada

Uma API FastAPI pode chamar:

```python
payload = dashboard_payload(records, alerts)
```

e retornar esse dicionário como JSON.

## Dependência

```bash
pip install -r tests/requirements.txt
```

## Testes

```bash
python -m unittest discover -s tests -v
```

## Exemplos

```bash
python windows_log_parser_pro.py stats ./logs --recursive --top 15
python windows_log_parser_pro.py hunt Security.evtx -o alerts.json
python windows_log_parser_pro.py parse Security.evtx -o events.db --event-id 4624 4625
```

Não publique logs reais, IPs, usernames ou outros dados sensíveis no repositório.
