# =========================================
# Анализ логов botsv1 (WinEventLog + DNS)
# =========================================

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# ---------- ЭТАП 1. Загрузка данных ----------

data = pd.read_json("botsv1.json")

# разворачиваем поле result в отдельный DataFrame
df = pd.json_normalize(data["result"])

# базовая очистка
df.columns = df.columns.str.strip()
df["EventCode"] = pd.to_numeric(df.get("EventCode"), errors="coerce")
df["_time"] = pd.to_datetime(df.get("_time"), errors="coerce")

print("Строк:", len(df), "| Колонок:", len(df.columns))


# ---------- ЭТАП 2. Анализ WinEvent ----------

# список потенциально опасных EventID
danger_ids = {4625, 4672, 4688, 4720}

win_events = df[df["EventCode"].isin(danger_ids)]
win_stat = win_events["EventCode"].value_counts()

print("\nПодозрительные события WinEvent:")
print(win_stat if not win_stat.empty else "Не обнаружены")


# ---------- ЭТАП 2. Анализ DNS ----------

dns_logs = df[df.get("sourcetype", "").astype(str).str.contains("dns", case=False)]

dns_stat = pd.Series()

if not dns_logs.empty and "query" in dns_logs.columns:

    # топ запросов
    dns_stat = dns_logs["query"].value_counts()

    # длинные домены (возможный DGA)
    long_domains = dns_logs[dns_logs["query"].str.len() > 50]

    print("\nТоп DNS-запросов:")
    print(dns_stat.head())

    print("\nПодозрительные длинные домены:")
    print(long_domains["query"].head())

else:
    print("\nDNS-записи не найдены.")


# ---------- ЭТАП 3. Визуализация ----------

# График WinEvent
if not win_stat.empty:
    plt.figure()
    sns.barplot(x=win_stat.index.astype(str),
                y=win_stat.values)
    plt.title("Топ подозрительных WinEvent")
    plt.xlabel("EventCode")
    plt.ylabel("Количество")
    plt.tight_layout()
    plt.show()

# График DNS
if not dns_stat.empty:
    top_dns = dns_stat.head(10)

    plt.figure()
    sns.barplot(x=top_dns.index,
                y=top_dns.values)
    plt.title("Топ-10 DNS-запросов")
    plt.xticks(rotation=70)
    plt.tight_layout()
    plt.show()

print("\nГотово.")
