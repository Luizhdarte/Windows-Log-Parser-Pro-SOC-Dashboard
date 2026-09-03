#!/usr/bin/env python3
r"""
windows_log_parser_pro.py
==========================

Parser/analisador avançado de logs do Windows.

FORMATOS DE ENTRADA
--------------------
  .evtx        Arquivos binários do Visualizador de Eventos (Security, System,
               Application, Sysmon, PowerShell/Operational etc).
               Requer: pip install python-evtx

  .csv         Exportação via: wevtutil qe <Log> /f:csv > logs.csv

  .txt / .log  Texto livre. Usa um regex configurável (--pattern) ou um preset
               (--preset generic|iis|syslog).

  .jsonl       Uma entrada JSON por linha (ex.: exportado de SIEM/Winlogbeat).
               Mapeamento de campos configurável via --field-map.

  Diretórios   Com --recursive, varre um diretório inteiro coletando todos os
               arquivos com extensão suportada.

SUBCOMANDOS
-----------
  parse   Extrai, filtra, deduplica e exporta os registros (JSON/CSV/JSONL/SQLite).
  stats   Gera um relatório estatístico (contagens por nível, Event ID, fonte,
          linha do tempo por hora) — em texto no console ou salvo em arquivo.
  hunt    Executa regras de detecção (brute-force, log limpo, escalonamento de
          privilégio etc.) e reporta alertas.

EXEMPLOS
--------
  # Parsear um .evtx e exportar só eventos de logon (4624/4625) para SQLite
  python windows_log_parser_pro.py parse Security.evtx -o eventos.db \
      --event-id 4624 4625

  # Estatísticas de uma pasta inteira de exports
  python windows_log_parser_pro.py stats ./logs --recursive --top 15

  # Caçar padrões suspeitos (força bruta, log limpo, etc.)
  python windows_log_parser_pro.py hunt Security.evtx -o alertas.json

  # Texto livre com preset de log IIS (W3C extended)
  python windows_log_parser_pro.py parse u_ex.log --preset iis -o saida.csv

  # JSONL com mapeamento de campos customizado
  python windows_log_parser_pro.py parse eventos.jsonl \
      --field-map '{"timestamp":"@timestamp","event_id":"winlog.event_id","level":"log.level","message":"message"}' \
      -o saida.json
"""

from __future__ import annotations

import argparse
import csv
import fnmatch
import json
import logging
import re
import sqlite3
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover
    ZoneInfo = None  # type: ignore

log = logging.getLogger("wlp")


# =============================================================================
# Modelo de dados
# =============================================================================

@dataclass
class LogRecord:
    timestamp: Optional[str] = None
    event_id: Optional[str] = None
    level: Optional[str] = None
    source: Optional[str] = None
    computer: Optional[str] = None
    user: Optional[str] = None
    ip_address: Optional[str] = None
    message: Optional[str] = None
    event_name: Optional[str] = None
    mitre_tactic: Optional[str] = None
    severity: Optional[str] = None
    file: Optional[str] = None
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self, include_raw: bool = True) -> dict[str, Any]:
        d = asdict(self)
        if not include_raw:
            d.pop("raw", None)
        return d

    def dt(self) -> Optional[datetime]:
        return parse_date_flexible(self.timestamp) if self.timestamp else None


# =============================================================================
# Base de conhecimento: Event IDs comuns do Windows
# (id -> (nome, tática MITRE ATT&CK aproximada, severidade sugerida))
# =============================================================================

KNOWN_EVENT_IDS: dict[str, tuple[str, str, str]] = {
    "1102": ("O log de auditoria foi limpo", "Defense Evasion", "Critical"),
    "104":  ("O log de eventos do sistema foi limpo", "Defense Evasion", "Critical"),
    "4624": ("Logon bem-sucedido", "Initial Access", "Information"),
    "4625": ("Falha de logon", "Credential Access", "Warning"),
    "4634": ("Logoff", "-", "Information"),
    "4648": ("Logon explícito com credenciais", "Lateral Movement", "Warning"),
    "4672": ("Logon com privilégios especiais (admin)", "Privilege Escalation", "Warning"),
    "4688": ("Novo processo criado", "Execution", "Information"),
    "4689": ("Processo encerrado", "-", "Information"),
    "4697": ("Serviço instalado no sistema", "Persistence", "Warning"),
    "4698": ("Tarefa agendada criada", "Persistence", "Warning"),
    "4720": ("Conta de usuário criada", "Persistence", "Warning"),
    "4722": ("Conta de usuário habilitada", "Persistence", "Information"),
    "4724": ("Tentativa de redefinição de senha", "Credential Access", "Warning"),
    "4728": ("Membro adicionado a grupo global habilitado p/ segurança", "Persistence", "Warning"),
    "4732": ("Membro adicionado a grupo local habilitado p/ segurança (ex.: Administradores)", "Privilege Escalation", "Warning"),
    "4740": ("Conta de usuário bloqueada", "Credential Access", "Warning"),
    "4756": ("Membro adicionado a grupo universal habilitado p/ segurança", "Persistence", "Warning"),
    "4768": ("Ticket Kerberos (TGT) solicitado", "Credential Access", "Information"),
    "4769": ("Ticket de serviço Kerberos solicitado", "Credential Access", "Information"),
    "4771": ("Falha de pré-autenticação Kerberos", "Credential Access", "Warning"),
    "4776": ("Tentativa de validação de credenciais (NTLM)", "Credential Access", "Information"),
    "5140": ("Compartilhamento de rede acessado", "Lateral Movement", "Information"),
    "5142": ("Compartilhamento de rede criado", "Persistence", "Warning"),
    "5145": ("Verificação de acesso a objeto de compartilhamento", "Discovery", "Information"),
    "7045": ("Novo serviço instalado (System log)", "Persistence", "Warning"),
    "1116": ("Windows Defender detectou malware", "-", "Critical"),
    "1117": ("Windows Defender executou uma ação sobre malware", "-", "Warning"),
}


def enrich_with_known_event(record: LogRecord) -> None:
    if record.event_id and record.event_id in KNOWN_EVENT_IDS:
        name, tactic, severity = KNOWN_EVENT_IDS[record.event_id]
        record.event_name = name
        record.mitre_tactic = tactic
        record.severity = severity


# Padrões comuns para extrair usuário/IP quando eles vêm embutidos na
# mensagem (típico de exports .csv/.txt do wevtutil, que não separam os
# campos de EventData em colunas próprias).
_USER_PATTERNS = [
    re.compile(r"TargetUserName=([^;]+)"),
    re.compile(r"SubjectUserName=([^;]+)"),
    re.compile(r"Account Name:\s*(\S+)"),
    # SSH / syslog: "Failed password for [invalid user] joao from 1.2.3.4"
    re.compile(r"[Ff]ailed password for (?:invalid user )?(\S+) from"),
    re.compile(r"[Ii]nvalid user (\S+) from"),
]
_IP_PATTERNS = [
    re.compile(r"IpAddress=([^;]+)"),
    re.compile(r"SourceAddress=([^;]+)"),
    re.compile(r"Source Network Address:\s*(\S+)"),
    # SSH / syslog: "... from 1.2.3.4 port 51000 ssh2"
    re.compile(r"from (\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+:[0-9a-fA-F:]+)\b"),
]


def fill_user_ip_from_message(record: LogRecord) -> None:
    if not record.message:
        return
    if not record.user:
        for pat in _USER_PATTERNS:
            m = pat.search(record.message)
            if m:
                value = m.group(1).strip()
                if value and value != "-":
                    record.user = value
                break
    if not record.ip_address:
        for pat in _IP_PATTERNS:
            m = pat.search(record.message)
            if m:
                value = m.group(1).strip()
                if value and value != "-":
                    record.ip_address = value
                break


# =============================================================================
# Descoberta de arquivos de entrada
# =============================================================================

SUPPORTED_EXTS = {".evtx", ".csv", ".txt", ".log", ".jsonl"}


def discover_input_files(inputs: list[str], recursive: bool) -> list[Path]:
    files: list[Path] = []
    for raw in inputs:
        p = Path(raw)
        if p.is_dir():
            pattern = "**/*" if recursive else "*"
            for child in sorted(p.glob(pattern)):
                if child.is_file() and child.suffix.lower() in SUPPORTED_EXTS:
                    files.append(child)
        elif any(ch in raw for ch in "*?[]"):
            matches = sorted(Path(m) for m in _glob_expand(raw))
            files.extend(m for m in matches if m.is_file())
        elif p.is_file():
            files.append(p)
        else:
            log.warning("Entrada não encontrada, ignorando: %s", raw)
    if not files:
        sys.exit("Nenhum arquivo de entrada válido encontrado.")
    return files


def _glob_expand(pattern: str) -> list[str]:
    base = Path(pattern).parent if Path(pattern).parent != Path(".") else Path(".")
    name_pattern = Path(pattern).name
    if not base.exists():
        return []
    return [str(p) for p in base.iterdir() if fnmatch.fnmatch(p.name, name_pattern)]


# =============================================================================
# Parsers por formato
# =============================================================================

def parse_evtx(path: Path) -> Iterator[LogRecord]:
    try:
        import Evtx.Evtx as evtx
        import xml.etree.ElementTree as ET
    except ImportError:
        sys.exit(
            "Erro: a biblioteca 'python-evtx' não está instalada.\n"
            "Instale com: pip install python-evtx"
        )

    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    level_map = {"1": "Critical", "2": "Error", "3": "Warning", "4": "Information", "5": "Verbose"}

    with evtx.Evtx(str(path)) as log_file:
        for record in log_file.records():
            xml_str = record.xml()
            try:
                root = ET.fromstring(xml_str)
            except ET.ParseError:
                continue

            system = root.find("e:System", ns)
            if system is None:
                continue

            def text_of(tag: str, attr: str | None = None) -> Optional[str]:
                el = system.find(f"e:{tag}", ns)
                if el is None:
                    return None
                return el.get(attr) if attr else el.text

            event_id = text_of("EventID")
            level = level_map.get(text_of("Level"), text_of("Level"))
            time_created = text_of("TimeCreated", "SystemTime")
            computer = text_of("Computer")
            provider = text_of("Provider", "Name")

            user, ip_address = None, None
            message_parts = []
            event_data = root.find("e:EventData", ns)
            if event_data is not None:
                for data_el in event_data.findall("e:Data", ns):
                    name = data_el.get("Name", "")
                    value = data_el.text or ""
                    if name in ("TargetUserName", "SubjectUserName", "AccountName") and not user:
                        user = value
                    if name in ("IpAddress", "SourceAddress") and not ip_address:
                        ip_address = value
                    message_parts.append(f"{name}={value}" if name else value)

            rec = LogRecord(
                timestamp=time_created,
                event_id=event_id,
                level=level,
                source=provider,
                computer=computer,
                user=user,
                ip_address=ip_address,
                message="; ".join(message_parts),
                file=str(path),
                raw={},
            )
            enrich_with_known_event(rec)
            yield rec


def parse_csv(path: Path) -> Iterator[LogRecord]:
    with open(path, newline="", encoding="utf-8-sig", errors="replace") as f:
        sample = f.read(2048)
        f.seek(0)
        try:
            has_header = bool(sample.strip()) and csv.Sniffer().has_header(sample)
        except csv.Error:
            has_header = False
        reader = csv.reader(f)

        header = [h.strip().lower() for h in next(reader)] if has_header else None

        for row in reader:
            if not row:
                continue
            if header:
                d = dict(zip(header, row))
                rec = LogRecord(
                    timestamp=d.get("date and time") or d.get("datetime") or d.get("timecreated"),
                    event_id=d.get("event id") or d.get("eventid"),
                    level=d.get("level"),
                    source=d.get("source"),
                    computer=d.get("computer"),
                    user=d.get("user") or d.get("username"),
                    message=d.get("message") or d.get("task category"),
                    file=str(path),
                    raw=d,
                )
            else:
                rec = LogRecord(
                    timestamp=row[1] if len(row) > 1 else None,
                    event_id=row[3] if len(row) > 3 else None,
                    level=row[0] if len(row) > 0 else None,
                    source=row[2] if len(row) > 2 else None,
                    message=row[-1] if row else None,
                    file=str(path),
                    raw={"columns": row},
                )
            enrich_with_known_event(rec)
            fill_user_ip_from_message(rec)
            yield rec


DEFAULT_TEXT_PATTERN = (
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)"
    r"\s*[-|]?\s*\[?(?P<level>[A-Za-z]+)\]?"
    r"\s*[-:]?\s*(?P<source>[\w.\-\\]+)?"
    r"\s*[-:]\s*(?P<message>.*)$"
)

SYSLOG_PATTERN = (
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<computer>\S+)\s+(?P<source>\S+?):\s*(?P<message>.*)$"
)


def parse_text(path: Path, pattern: Optional[str] = None, preset: str = "generic") -> Iterator[LogRecord]:
    if preset == "iis":
        yield from _parse_iis_w3c(path)
        return

    if preset == "syslog":
        compiled = re.compile(SYSLOG_PATTERN)
    else:
        compiled = re.compile(pattern or DEFAULT_TEXT_PATTERN)

    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.strip() or line.startswith("#"):
                continue
            m = compiled.match(line)
            if m:
                gd = m.groupdict()
                rec = LogRecord(
                    timestamp=gd.get("timestamp"),
                    event_id=gd.get("event_id"),
                    level=gd.get("level"),
                    source=gd.get("source"),
                    computer=gd.get("computer"),
                    user=gd.get("user"),
                    ip_address=gd.get("ip_address"),
                    message=gd.get("message", line),
                    file=str(path),
                    raw={"line": line},
                )
            else:
                rec = LogRecord(message=line, file=str(path), raw={"line": line, "unmatched": True})
            enrich_with_known_event(rec)
            fill_user_ip_from_message(rec)
            yield rec


def _parse_iis_w3c(path: Path) -> Iterator[LogRecord]:
    """Parseia logs IIS no formato W3C Extended (linhas '#Fields:' definem colunas)."""
    fields: list[str] = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            if line.startswith("#Fields:"):
                fields = line.split(":", 1)[1].strip().split(" ")
                continue
            if line.startswith("#"):
                continue
            if not fields:
                continue
            values = line.split(" ")
            d = dict(zip(fields, values))
            timestamp = None
            if "date" in d and "time" in d:
                timestamp = f"{d['date']}T{d['time']}"
            rec = LogRecord(
                timestamp=timestamp,
                source="IIS",
                computer=d.get("s-ip"),
                user=d.get("cs-username") if d.get("cs-username") not in (None, "-") else None,
                ip_address=d.get("c-ip"),
                message=f"{d.get('cs-method','')} {d.get('cs-uri-stem','')} -> {d.get('sc-status','')}",
                file=str(path),
                raw=d,
            )
            yield rec


DEFAULT_FIELD_MAP = {
    "timestamp": "timestamp", "event_id": "event_id", "level": "level",
    "source": "source", "computer": "computer", "user": "user",
    "ip_address": "ip_address", "message": "message",
}


def parse_jsonl(path: Path, field_map: Optional[dict[str, str]] = None) -> Iterator[LogRecord]:
    fm = {**DEFAULT_FIELD_MAP, **(field_map or {})}

    def dig(d: dict, dotted_key: str) -> Optional[str]:
        cur: Any = d
        for part in dotted_key.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                return None
        # Só aceitamos valores primitivos (str/int/float/bool). Se o caminho
        # apontar para um dict/list (campo mal mapeado), tratamos como ausente
        # em vez de propagar um objeto não hasheável pelo resto do pipeline.
        if isinstance(cur, (dict, list)):
            return None
        return str(cur) if cur is not None else None

    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                log.debug("Linha JSONL inválida ignorada: %s", line[:80])
                continue
            rec = LogRecord(
                timestamp=dig(obj, fm["timestamp"]),
                event_id=dig(obj, fm["event_id"]),
                level=dig(obj, fm["level"]),
                source=dig(obj, fm["source"]),
                computer=dig(obj, fm["computer"]),
                user=dig(obj, fm["user"]),
                ip_address=dig(obj, fm["ip_address"]),
                message=dig(obj, fm["message"]),
                file=str(path),
                raw=obj,
            )
            enrich_with_known_event(rec)
            yield rec


def detect_format(path: Path, forced: Optional[str] = None) -> str:
    if forced:
        return forced
    ext = path.suffix.lower().lstrip(".")
    return {"evtx": "evtx", "csv": "csv", "jsonl": "jsonl", "txt": "text", "log": "text"}.get(ext, "text")


def parse_file(
    path: Path,
    forced_format: Optional[str] = None,
    pattern: Optional[str] = None,
    preset: str = "generic",
    field_map: Optional[dict[str, str]] = None,
) -> Iterator[LogRecord]:
    fmt = detect_format(path, forced_format)
    log.info("Lendo %s (%s)", path, fmt)
    if fmt == "evtx":
        yield from parse_evtx(path)
    elif fmt == "csv":
        yield from parse_csv(path)
    elif fmt == "jsonl":
        yield from parse_jsonl(path, field_map)
    else:
        yield from parse_text(path, pattern=pattern, preset=preset)


# =============================================================================
# Utilidades de data / timezone
# =============================================================================

def parse_date_flexible(value: str) -> Optional[datetime]:
    value = value.strip()
    formats = [
        "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S", "%Y-%m-%d",
        "%m/%d/%Y %H:%M:%S", "%m/%d/%Y",
        "%b %d %H:%M:%S",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


def convert_timezone(records: Iterable[LogRecord], target_tz: str) -> None:
    if ZoneInfo is None:
        log.warning("zoneinfo indisponível; ignorando conversão de fuso horário.")
        return
    try:
        tz = ZoneInfo(target_tz)
    except Exception:
        log.warning("Fuso horário inválido: %s", target_tz)
        return
    for r in records:
        dt = r.dt()
        if dt:
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=ZoneInfo("UTC"))
            r.timestamp = dt.astimezone(tz).isoformat()


# =============================================================================
# Filtros e deduplicação
# =============================================================================

def filter_records(
    records: Iterable[LogRecord],
    event_ids: Optional[list[str]] = None,
    exclude_event_ids: Optional[list[str]] = None,
    level: Optional[str] = None,
    keyword: Optional[str] = None,
    exclude_keyword: Optional[str] = None,
    user: Optional[str] = None,
    ip_address: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
) -> list[LogRecord]:
    start_dt = parse_date_flexible(start_date) if start_date else None
    end_dt = parse_date_flexible(end_date) if end_date else None

    out = []
    for r in records:
        if event_ids and r.event_id not in event_ids:
            continue
        if exclude_event_ids and r.event_id in exclude_event_ids:
            continue
        if level and (not r.level or r.level.lower() != level.lower()):
            continue
        if keyword and keyword.lower() not in (r.message or "").lower():
            continue
        if exclude_keyword and exclude_keyword.lower() in (r.message or "").lower():
            continue
        if user and (not r.user or user.lower() not in r.user.lower()):
            continue
        if ip_address and r.ip_address != ip_address:
            continue
        if start_dt or end_dt:
            dt = r.dt()
            if dt is None:
                continue
            if start_dt and dt < start_dt:
                continue
            if end_dt and dt > end_dt:
                continue
        out.append(r)
    return out


def deduplicate(records: list[LogRecord]) -> list[LogRecord]:
    seen: set[tuple] = set()
    result = []
    for r in records:
        key = (r.timestamp, r.event_id, r.source, r.message)
        if key in seen:
            continue
        seen.add(key)
        result.append(r)
    return result


# =============================================================================
# Estatísticas
# =============================================================================

def compute_stats(records: list[LogRecord]) -> dict[str, Any]:
    by_level = Counter(r.level or "Desconhecido" for r in records)
    by_event_id = Counter(r.event_id for r in records if r.event_id)
    by_source = Counter(r.source or "Desconhecido" for r in records)
    by_user = Counter(r.user for r in records if r.user)
    by_hour: Counter = Counter()
    first_ts, last_ts = None, None

    for r in records:
        dt = r.dt()
        if dt:
            by_hour[dt.strftime("%Y-%m-%d %H:00")] += 1
            if first_ts is None or dt < first_ts:
                first_ts = dt
            if last_ts is None or dt > last_ts:
                last_ts = dt

    return {
        "total": len(records),
        "by_level": by_level,
        "by_event_id": by_event_id,
        "by_source": by_source,
        "by_user": by_user,
        "by_hour": dict(sorted(by_hour.items())),
        "first_timestamp": first_ts.isoformat() if first_ts else None,
        "last_timestamp": last_ts.isoformat() if last_ts else None,
    }


def dashboard_payload(records: list[LogRecord], alerts: Optional[list[Alert]] = None) -> dict[str, Any]:
    """Retorna um payload JSON estável para dashboards/API."""
    stats = compute_stats(records)
    alerts = alerts or []
    return {
        "generated_at": datetime.now().astimezone().isoformat(),
        "summary": {
            "total_events": stats["total"],
            "alerts": len(alerts),
            "critical_alerts": sum(a.severity == "Critical" for a in alerts),
            "high_alerts": sum(a.severity == "High" for a in alerts),
            "unique_ips": len({r.ip_address for r in records if r.ip_address}),
        },
        "levels": dict(stats["by_level"]),
        "event_ids": dict(stats["by_event_id"].most_common(15)),
        "sources": dict(stats["by_source"].most_common(15)),
        "users": dict(stats["by_user"].most_common(15)),
        "timeline": stats["by_hour"],
        "alerts": [a.to_dict() for a in alerts],
    }


def render_stats_report(stats: dict[str, Any], top: int = 10) -> str:
    lines = []
    lines.append("=" * 60)
    lines.append("RELATÓRIO DE ESTATÍSTICAS DE LOGS")
    lines.append("=" * 60)
    lines.append(f"Total de registros : {stats['total']}")
    lines.append(f"Período            : {stats['first_timestamp']} -> {stats['last_timestamp']}")
    lines.append("")

    lines.append("-- Por nível --")
    for level, count in stats["by_level"].most_common():
        lines.append(f"  {level:<15} {count}")

    lines.append("")
    lines.append(f"-- Top {top} Event IDs --")
    for eid, count in stats["by_event_id"].most_common(top):
        name = KNOWN_EVENT_IDS.get(eid, (None,))[0]
        label = f"{eid} ({name})" if name else eid
        lines.append(f"  {label:<55} {count}")

    lines.append("")
    lines.append(f"-- Top {top} fontes (Source) --")
    for source, count in stats["by_source"].most_common(top):
        lines.append(f"  {source:<40} {count}")

    if stats["by_user"]:
        lines.append("")
        lines.append(f"-- Top {top} usuários --")
        for user, count in stats["by_user"].most_common(top):
            lines.append(f"  {user:<30} {count}")

    if stats["by_hour"]:
        lines.append("")
        lines.append("-- Linha do tempo (eventos por hora) --")
        max_count = max(stats["by_hour"].values())
        for hour, count in stats["by_hour"].items():
            bar_len = int((count / max_count) * 40) if max_count else 0
            lines.append(f"  {hour}  {'#' * bar_len} {count}")

    lines.append("=" * 60)
    return "\n".join(lines)


# =============================================================================
# Motor de detecção (regras)
# =============================================================================

@dataclass
class Alert:
    rule: str
    severity: str
    description: str
    records: list[LogRecord] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "description": self.description,
            "record_count": len(self.records),
            "sample": [r.to_dict(include_raw=False) for r in self.records[:5]],
        }


def _is_windows_logon_failure(r: LogRecord) -> bool:
    return r.event_id == "4625"


_RDP_LOGONTYPE_PATTERNS = [
    re.compile(r"LogonType=10\b"),
    re.compile(r"Logon Type:\s*10\b"),
]


def _is_rdp_logon_failure(r: LogRecord) -> bool:
    """Falha de logon 4625 cujo LogonType=10 indica origem via RDP (rede/terminal service)."""
    if r.event_id != "4625" or not r.message:
        return False
    return any(pat.search(r.message) for pat in _RDP_LOGONTYPE_PATTERNS)


_WEB_STATUS_PATTERN = re.compile(r"->\s*(\d{3})\b")


def _is_web_auth_failure(r: LogRecord) -> bool:
    """Falha de autenticação HTTP (401/403) — logs IIS ou outro texto no mesmo formato."""
    if not r.message:
        return False
    m = _WEB_STATUS_PATTERN.search(r.message)
    return bool(m) and m.group(1) in ("401", "403")


_SSH_FAILURE_PATTERN = re.compile(r"failed password|authentication failure|invalid user", re.IGNORECASE)


def _is_ssh_failure(r: LogRecord) -> bool:
    """Falha de autenticação SSH (linhas típicas de sshd em syslog/auth.log)."""
    if not r.message:
        return False
    return bool(_SSH_FAILURE_PATTERN.search(r.message))


# Categoria -> (função detectora, rótulo amigável)
FAILURE_CATEGORIES: dict[str, tuple[Any, str]] = {
    "windows_logon": (_is_windows_logon_failure, "Logon do Windows"),
    "rdp_logon": (_is_rdp_logon_failure, "Logon via RDP"),
    "web_auth": (_is_web_auth_failure, "Autenticação Web (HTTP 401/403)"),
    "ssh_logon": (_is_ssh_failure, "Logon SSH"),
}


def rule_brute_force(
    records: list[LogRecord],
    window_minutes: int = 10,
    threshold: int = 5,
    categories: Optional[list[str]] = None,
) -> list[Alert]:
    """Detecta rajadas de falhas de autenticação para a mesma conta/IP em uma
    janela curta de tempo, em qualquer uma das categorias suportadas:
    logon do Windows, RDP, autenticação Web (IIS 401/403) e SSH.

    Um mesmo evento 4625 com LogonType=10 conta tanto para 'windows_logon'
    quanto para 'rdp_logon' (é um logon de rede que também é via RDP) — isso
    é intencional, para não esconder o vetor específico em nenhuma das visões.
    """
    cat_names = categories or list(FAILURE_CATEGORIES.keys())
    window = timedelta(minutes=window_minutes)
    alerts: list[Alert] = []

    for cat_name in cat_names:
        entry = FAILURE_CATEGORIES.get(cat_name)
        if not entry:
            log.warning("Categoria de força bruta desconhecida: %s", cat_name)
            continue
        detector, label = entry

        matched = [r for r in records if r.dt() and detector(r)]
        matched.sort(key=lambda r: r.dt())

        buckets: dict[str, list[LogRecord]] = defaultdict(list)
        for r in matched:
            key = r.user or r.ip_address or r.computer or "desconhecido"
            buckets[key].append(r)

        for key, recs in buckets.items():
            i = 0
            for j in range(len(recs)):
                while recs[j].dt() - recs[i].dt() > window:
                    i += 1
                count = j - i + 1
                if count >= threshold:
                    alerts.append(Alert(
                        rule=f"brute_force_{cat_name}",
                        severity="High",
                        description=(
                            f"[{label}] {count} falhas de autenticação para "
                            f"'{key}' em {window_minutes} min."
                        ),
                        records=recs[i:j + 1],
                    ))
                    break
    return alerts


def rule_log_cleared(records: list[LogRecord]) -> list[Alert]:
    hits = [r for r in records if r.event_id in ("1102", "104")]
    if not hits:
        return []
    return [Alert(
        rule="log_cleared",
        severity="Critical",
        description=f"Log de auditoria/sistema limpo {len(hits)} vez(es) — possível cobertura de rastros.",
        records=hits,
    )]


def rule_privilege_escalation(
    records: list[LogRecord], window_minutes: int = 60
) -> list[Alert]:
    """Detecta 4720 seguido de 4732 para o mesmo usuário dentro de uma janela."""
    window = timedelta(minutes=window_minutes)
    created = [r for r in records if r.event_id == "4720" and r.user and r.dt()]
    escalated = [r for r in records if r.event_id == "4732" and r.user and r.dt()]
    alerts: list[Alert] = []

    for added in escalated:
        candidates = [
            c for c in created
            if c.user == added.user
            and c.dt() <= added.dt()
            and added.dt() - c.dt() <= window
        ]
        if candidates:
            created_rec = max(candidates, key=lambda r: r.dt())
            alerts.append(Alert(
                rule="new_user_privilege_escalation",
                severity="High",
                description=(
                    f"Usuário '{added.user}' criado e adicionado a grupo privilegiado "
                    f"em até {window_minutes} min."
                ),
                records=[created_rec, added],
            ))
    return alerts


def rule_account_lockout_spike(records: list[LogRecord], threshold: int = 3) -> list[Alert]:
    lockouts = [r for r in records if r.event_id == "4740"]
    if len(lockouts) >= threshold:
        return [Alert(
            rule="account_lockout_spike",
            severity="Medium",
            description=f"{len(lockouts)} bloqueios de conta detectados no período analisado.",
            records=lockouts,
        )]
    return []


DETECTION_RULES = {
    "brute_force": rule_brute_force,
    "log_cleared": rule_log_cleared,
    "privilege_escalation": rule_privilege_escalation,
    "account_lockout_spike": rule_account_lockout_spike,
}


def run_detection(records: list[LogRecord], enabled_rules: Optional[list[str]] = None) -> list[Alert]:
    rules = enabled_rules or list(DETECTION_RULES.keys())
    alerts: list[Alert] = []
    for name in rules:
        func = DETECTION_RULES.get(name)
        if not func:
            log.warning("Regra de detecção desconhecida: %s", name)
            continue
        alerts.extend(func(records))
    return alerts


# =============================================================================
# Exportação
# =============================================================================

def export_json(records: list[LogRecord], path: Path) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump([r.to_dict() for r in records], f, ensure_ascii=False, indent=2, default=str)


def export_jsonl(records: list[LogRecord], path: Path) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r.to_dict(), ensure_ascii=False, default=str) + "\n")


def export_csv(records: list[LogRecord], path: Path) -> None:
    fieldnames = ["timestamp", "event_id", "event_name", "level", "severity", "source",
                  "computer", "user", "ip_address", "mitre_tactic", "message"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in records:
            writer.writerow({k: getattr(r, k) for k in fieldnames})


def export_sqlite(records: list[LogRecord], path: Path) -> None:
    conn = sqlite3.connect(str(path))
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT, event_id TEXT, event_name TEXT, level TEXT, severity TEXT,
            source TEXT, computer TEXT, user TEXT, ip_address TEXT,
            mitre_tactic TEXT, message TEXT, file TEXT, raw_json TEXT
        )
    """)
    cur.executemany(
        """INSERT INTO logs
           (timestamp, event_id, event_name, level, severity, source, computer, user,
            ip_address, mitre_tactic, message, file, raw_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        [
            (r.timestamp, r.event_id, r.event_name, r.level, r.source, r.computer,
             r.user, r.ip_address, r.mitre_tactic, r.message, r.file,
             json.dumps(r.raw, ensure_ascii=False, default=str))
            for r in records
        ],
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_event_id ON logs(event_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON logs(timestamp)")
    conn.commit()
    conn.close()


def export_records(records: list[LogRecord], path: Path) -> None:
    ext = path.suffix.lower().lstrip(".")
    if ext == "json":
        export_json(records, path)
    elif ext == "jsonl":
        export_jsonl(records, path)
    elif ext == "csv":
        export_csv(records, path)
    elif ext in ("db", "sqlite", "sqlite3"):
        export_sqlite(records, path)
    else:
        sys.exit(f"Extensão de saída não suportada: .{ext} (use json, jsonl, csv ou db)")


def export_alerts(alerts: list[Alert], path: Path) -> None:
    ext = path.suffix.lower().lstrip(".")
    data = [a.to_dict() for a in alerts]
    if ext == "json":
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2, default=str)
    else:
        with open(path, "w", encoding="utf-8") as f:
            for a in data:
                f.write(f"[{a['severity']}] {a['rule']}: {a['description']} "
                        f"({a['record_count']} registro(s))\n")


# =============================================================================
# Pipeline compartilhado
# =============================================================================

def load_records(args: argparse.Namespace) -> list[LogRecord]:
    field_map = json.loads(args.field_map) if getattr(args, "field_map", None) else None
    files = discover_input_files(args.input, getattr(args, "recursive", False))

    records: list[LogRecord] = []
    for path in files:
        records.extend(parse_file(
            path,
            forced_format=getattr(args, "format", None),
            pattern=getattr(args, "pattern", None),
            preset=getattr(args, "preset", "generic"),
            field_map=field_map,
        ))
    log.info("Total bruto de registros lidos: %d", len(records))

    records = filter_records(
        records,
        event_ids=getattr(args, "event_id", None),
        exclude_event_ids=getattr(args, "exclude_event_id", None),
        level=getattr(args, "level", None),
        keyword=getattr(args, "keyword", None),
        exclude_keyword=getattr(args, "exclude_keyword", None),
        user=getattr(args, "user", None),
        ip_address=getattr(args, "ip", None),
        start_date=getattr(args, "start_date", None),
        end_date=getattr(args, "end_date", None),
    )

    if getattr(args, "dedup", False):
        before = len(records)
        records = deduplicate(records)
        log.info("Deduplicação: %d -> %d registros", before, len(records))

    if getattr(args, "tz", None):
        convert_timezone(records, args.tz)

    return records


# =============================================================================
# CLI
# =============================================================================

def add_common_input_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("input", nargs="+", help="Arquivo(s), pasta(s) ou padrão glob de entrada")
    p.add_argument("--recursive", action="store_true", help="Varre subpastas ao receber diretórios")
    p.add_argument("--format", choices=["evtx", "csv", "text", "jsonl"], help="Força o formato (senão detecta pela extensão)")
    p.add_argument("--preset", choices=["generic", "iis", "syslog"], default="generic", help="Preset de regex para logs de texto")
    p.add_argument("--pattern", help="Regex customizado para texto livre (grupos nomeados)")
    p.add_argument("--field-map", help="JSON mapeando campos para entradas .jsonl, ex: '{\"timestamp\":\"@timestamp\"}'")
    p.add_argument("--event-id", nargs="+", help="Filtra por Event ID(s)")
    p.add_argument("--exclude-event-id", nargs="+", help="Exclui Event ID(s)")
    p.add_argument("--level", help="Filtra por nível (Error, Warning, Information...)")
    p.add_argument("--keyword", help="Filtra por palavra-chave na mensagem")
    p.add_argument("--exclude-keyword", help="Exclui registros que contêm esta palavra-chave")
    p.add_argument("--user", help="Filtra por usuário (substring)")
    p.add_argument("--ip", help="Filtra por endereço IP exato")
    p.add_argument("--start-date", help="Data/hora inicial")
    p.add_argument("--end-date", help="Data/hora final")
    p.add_argument("--dedup", action="store_true", help="Remove registros duplicados")
    p.add_argument("--tz", help="Converte timestamps para este fuso horário (ex: America/Sao_Paulo)")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Parser e analisador avançado de logs do Windows.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Log detalhado (debug)")
    sub = parser.add_subparsers(dest="command", required=True)

    p_parse = sub.add_parser("parse", help="Extrai, filtra e exporta registros")
    add_common_input_args(p_parse)
    p_parse.add_argument("-v", "--verbose", action="store_true", help="Log detalhado (debug)")
    p_parse.add_argument("-o", "--output", type=Path, required=True, help="Saída: .json, .jsonl, .csv ou .db (SQLite)")

    p_stats = sub.add_parser("stats", help="Gera relatório estatístico")
    add_common_input_args(p_stats)
    p_stats.add_argument("-v", "--verbose", action="store_true", help="Log detalhado (debug)")
    p_stats.add_argument("--top", type=int, default=10, help="Quantos itens mostrar em cada ranking")
    p_stats.add_argument("-o", "--output", type=Path, help="Salva o relatório em arquivo de texto (senão imprime no console)")

    p_hunt = sub.add_parser("hunt", help="Executa regras de detecção de padrões suspeitos")
    add_common_input_args(p_hunt)
    p_hunt.add_argument("-v", "--verbose", action="store_true", help="Log detalhado (debug)")
    p_hunt.add_argument("--rules", nargs="+", choices=list(DETECTION_RULES.keys()), help="Regras específicas a executar (senão roda todas)")
    p_hunt.add_argument("--window-minutes", type=int, default=10, help="Janela (min) para regra de força bruta")
    p_hunt.add_argument("--threshold", type=int, default=5, help="Limite de eventos para força bruta")
    p_hunt.add_argument(
        "--brute-force-categories", nargs="+", choices=list(FAILURE_CATEGORIES.keys()),
        help="Restringe a força bruta a categorias específicas (senão roda todas: "
             + ", ".join(FAILURE_CATEGORIES.keys()) + ")",
    )
    p_hunt.add_argument("-o", "--output", type=Path, help="Salva alertas em .json ou .txt (senão imprime no console)")

    args = parser.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    records = load_records(args)

    if args.command == "parse":
        export_records(records, args.output)
        print(f"{len(records)} registro(s) exportado(s) para {args.output}")

    elif args.command == "stats":
        stats = compute_stats(records)
        report = render_stats_report(stats, top=args.top)
        if args.output:
            args.output.write_text(report, encoding="utf-8")
            print(f"Relatório salvo em {args.output}")
        else:
            print(report)

    elif args.command == "hunt":
        selected_rules = args.rules or list(DETECTION_RULES.keys())
        alerts: list[Alert] = []

        if "brute_force" in selected_rules:
            alerts.extend(rule_brute_force(
                records, args.window_minutes, args.threshold,
                categories=args.brute_force_categories,
            ))
        if "log_cleared" in selected_rules:
            alerts.extend(rule_log_cleared(records))
        if "privilege_escalation" in selected_rules:
            alerts.extend(rule_privilege_escalation(records))
        if "account_lockout_spike" in selected_rules:
            alerts.extend(rule_account_lockout_spike(records))

        if not alerts:
            print("Nenhum alerta gerado pelas regras selecionadas.")
        else:
            print(f"{len(alerts)} alerta(s) gerado(s):\n")
            for a in alerts:
                print(f"  [{a.severity}] {a.rule}: {a.description}")
        if args.output:
            export_alerts(alerts, args.output)
            print(f"\nAlertas salvos em {args.output}")


if __name__ == "__main__":
    main()
