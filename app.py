import platform
import re
import socket
import subprocess
from datetime import datetime
from typing import Dict, List

import pandas as pd
import plotly.express as px
import streamlit as st


APP_TITLE = "NetOps Command Center"
DEFAULT_CHECK_HOSTS = ["google.com", "cloudflare.com", "github.com"]
DEFAULT_PORTS = [22, 53, 80, 443, 8080]


def parse_ping_latency(output: str) -> float | None:
    patterns = [r"Average = ([0-9]+)ms", r"time[=<]\s*([0-9.]+)\s*ms"]
    for pattern in patterns:
        match = re.search(pattern, output)
        if match:
            try:
                return float(match.group(1))
            except ValueError:
                continue
    return None


def ping_host(target: str) -> Dict:
    count_flag = "-n" if platform.system().lower().startswith("win") else "-c"
    command = ["ping", count_flag, "1", target]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=12,
        )
        output = completed.stdout + completed.stderr
        reachable = completed.returncode == 0
        latency = parse_ping_latency(output) if reachable else None
        return {
            "target": target,
            "reachable": reachable,
            "latency_ms": latency,
            "output": output.strip(),
            "status": "Healthy" if reachable else "Unreachable",
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "target": target,
            "reachable": False,
            "latency_ms": None,
            "output": f"Timeout expired: {exc}",
            "status": "Timeout",
        }
    except Exception as exc:
        return {
            "target": target,
            "reachable": False,
            "latency_ms": None,
            "output": str(exc),
            "status": "Error",
        }


def resolve_dns(target: str) -> Dict:
    try:
        _, _, addresses = socket.gethostbyname_ex(target)
        return {
            "target": target,
            "resolved": True,
            "addresses": addresses,
            "status": "Resolved",
        }
    except Exception as exc:
        return {
            "target": target,
            "resolved": False,
            "addresses": [],
            "status": "Failure",
            "error": str(exc),
        }


def scan_ports(host: str, ports: List[int]) -> List[Dict]:
    results = []
    for port in ports:
        status = "Closed"
        error = None
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2)
                code = sock.connect_ex((host, port))
                if code == 0:
                    status = "Open"
                else:
                    status = "Closed"
        except Exception as exc:
            status = "Error"
            error = str(exc)
        results.append({"host": host, "port": port, "status": status, "error": error})
    return results


def classify_incident(entry: Dict) -> str:
    severity = "P3"
    if entry["type"] == "ping":
        if not entry["status"] or entry["status"] == "Unreachable":
            severity = "P1"
        elif entry["latency_ms"] is not None and entry["latency_ms"] > 250:
            severity = "P2"
    elif entry["type"] == "dns":
        if not entry["resolved"]:
            severity = "P1"
    elif entry["type"] == "port":
        if entry["status"] == "Closed":
            severity = "P2"
        if entry["status"] == "Error":
            severity = "P1"
    return severity


def build_incident_log(ping_results: List[Dict], dns_results: List[Dict], port_results: List[Dict]) -> pd.DataFrame:
    rows = []
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for item in ping_results:
        if not item["reachable"] or (item["latency_ms"] is not None and item["latency_ms"] > 250):
            entry = {
                "timestamp": timestamp,
                "type": "ping",
                "target": item["target"],
                "status": item["status"],
                "detail": item["status"],
                "latency_ms": item["latency_ms"],
            }
            entry["severity"] = classify_incident(entry)
            rows.append(entry)

    for item in dns_results:
        if not item["resolved"]:
            entry = {
                "timestamp": timestamp,
                "type": "dns",
                "target": item["target"],
                "resolved": item["resolved"],
                "detail": item.get("error", "DNS lookup failed"),
                "latency_ms": None,
            }
            entry["severity"] = classify_incident(entry)
            rows.append(entry)

    for item in port_results:
        if item["status"] != "Open":
            entry = {
                "timestamp": timestamp,
                "type": "port",
                "target": f"{item['host']}:{item['port']}",
                "status": item["status"],
                "detail": item["status"] if item["error"] is None else item["error"],
                "latency_ms": None,
            }
            entry["severity"] = classify_incident(entry)
            rows.append(entry)

    if not rows:
        rows.append(
            {
                "timestamp": timestamp,
                "type": "health",
                "target": "all checks",
                "detail": "All monitored systems are healthy.",
                "latency_ms": None,
                "severity": "P3",
            }
        )

    return pd.DataFrame(rows)


def generate_rca(incident_df: pd.DataFrame) -> str:
    if incident_df.empty:
        return "No incidents detected. Network and services are operating normally."

    lines = ["Root Cause Analysis Report", "===========================", ""]
    lines.append(f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")

    severity_counts = incident_df["severity"].value_counts().to_dict()
    lines.append("Incident Summary")
    for severity in ["P1", "P2", "P3"]:
        if severity in severity_counts:
            lines.append(f"- {severity}: {severity_counts[severity]}")
    lines.append("")

    for _, row in incident_df.iterrows():
        lines.append(f"Target: {row['target']}")
        lines.append(f"Type: {row['type'].upper()}")
        lines.append(f"Severity: {row['severity']}")
        lines.append(f"Details: {row['detail']}")
        if row["type"] == "ping" and row["latency_ms"] is not None:
            lines.append(f"Measured latency: {row['latency_ms']} ms")
        lines.append("")

    if any(row["type"] == "dns" for _, row in incident_df.iterrows()):
        lines.append("Likely cause: DNS resolution failure or external resolver outage.")
    if any(row["type"] == "ping" and row["detail"] == "Unreachable" for _, row in incident_df.iterrows()):
        lines.append("Likely cause: Network connectivity issue or destination host outage.")
    if any(row["type"] == "port" and row["detail"] == "Closed" for _, row in incident_df.iterrows()):
        lines.append("Likely cause: service port blocked by firewall, service down, or ACL violation.")

    lines.append("")
    lines.append("Recommended next steps:")
    lines.append("1. Validate local network connectivity and default gateway.")
    lines.append("2. Verify DNS settings and resolver availability.")
    lines.append("3. Confirm target service ports are listening and firewall rules allow access.")
    lines.append("4. Escalate to infrastructure or ISP teams if external sites remain unreachable.")

    return "\n".join(lines)


def format_status(kind: str, value: bool) -> str:
    return "Healthy" if value else kind


def main() -> None:
    st.set_page_config(page_title=APP_TITLE, layout="wide", page_icon="📡")
    st.markdown(
        "<style>"
        "header {visibility: hidden;}"
        "footer {visibility: hidden;}"
        "</style>",
        unsafe_allow_html=True,
    )

    st.markdown(
        "# 📡 NetOps Command Center"
        "\n" "Professional network monitoring, diagnostics, and incident automation for GitHub-ready demos."
    )

    with st.sidebar:
        st.header("Controls")
        host_input = st.text_input(
            "Website to monitor",
            value="github.com",
            help="Enter a hostname or URL to test ping, DNS, and ports.",
        )
        dns_targets = st.text_area(
            "DNS resolution targets",
            value="\n".join(DEFAULT_CHECK_HOSTS),
            help="Enter one host per line for DNS and ping health checks.",
            height=120,
        )
        scan_host = st.text_input(
            "Port scan host", value="github.com", help="Enter the target host for optional port scanning."
        )
        port_list = st.text_input(
            "Ports to scan",
            value=", ".join(str(port) for port in DEFAULT_PORTS),
            help="List ports separated by commas.",
        )
        if st.button("Run full health check"):
            st.experimental_rerun()

    check_hosts = [line.strip() for line in dns_targets.splitlines() if line.strip()]
    scan_ports_list = [int(port.strip()) for port in port_list.split(",") if port.strip().isdigit()]

    with st.spinner("Running health diagnostics..."):
        default_ping = [ping_host(target) for target in check_hosts]
        default_dns = [resolve_dns(target) for target in check_hosts]
        selected_ping = ping_host(host_input)
        selected_dns = resolve_dns(host_input)
        selected_ports = scan_ports(scan_host, scan_ports_list)

    ping_df = pd.DataFrame(default_ping)
    dns_df = pd.DataFrame(default_dns)
    port_df = pd.DataFrame(selected_ports)

    incident_df = build_incident_log([selected_ping] + default_ping, [selected_dns] + default_dns, selected_ports)
    severity_counts = incident_df["severity"].value_counts().reindex(["P1", "P2", "P3"], fill_value=0)

    top1, top2, top3 = st.columns([2, 2, 1])
    top1.metric("Monitored hosts", len(check_hosts) + 1)
    top2.metric("Detected incidents", len(incident_df) - (1 if incident_df.iloc[0]["type"] == "health" else 0))
    top3.metric("Highest severity", severity_counts[severity_counts.gt(0)].index[0] if severity_counts.sum() else "None")

    col_a, col_b = st.columns(2)
    with col_a:
        st.subheader("Network Health Summary")
        health_status = "Healthy"
        if any(not item["reachable"] for item in default_ping):
            health_status = "Degraded"
        if all(not item["reachable"] for item in default_ping):
            health_status = "Critical"
        st.info(f"**Overall status:** {health_status}")

        severity_df = pd.DataFrame({
            "Severity": severity_counts.index.astype(str),
            "Count": severity_counts.values,
        })
        fig = px.bar(
            severity_df,
            x="Severity",
            y="Count",
            color="Severity",
            color_discrete_map={"P1": "red", "P2": "orange", "P3": "green"},
            title="Incident Severity Breakdown",
        )
        st.plotly_chart(fig, use_container_width=True)

        st.markdown("### Latest incident log")
        st.dataframe(incident_df if len(incident_df) <= 20 else incident_df.head(20), height=320)

    with col_b:
        st.subheader("Live diagnostics")
        ping_cols = st.columns(3)
        for idx, item in enumerate([selected_ping] + default_ping):
            with ping_cols[idx % 3]:
                status = "✅" if item["reachable"] else "⛔"
                latency = f"{item['latency_ms']} ms" if item["latency_ms"] is not None else "n/a"
                st.metric(label=item["target"], value=status, delta=latency)

        st.markdown("#### DNS lookup results")
        st.table(
            pd.DataFrame(
                [
                    {
                        "Host": item["target"],
                        "Status": item["status"],
                        "Addresses": ", ".join(item["addresses"]) if item["resolved"] else item.get("error", "n/a"),
                    }
                    for item in [selected_dns] + default_dns
                ]
            )
        )

        st.markdown("#### Port scan results")
        if port_df.empty:
            st.write("No ports selected for scanning.")
        else:
            st.table(port_df.rename(columns={"host": "Host", "port": "Port", "status": "Status", "error": "Error"}))

    st.markdown("---")
    tab1, tab2, tab3 = st.tabs(["Diagnostics", "RCA Report", "Export"])

    with tab1:
        st.subheader("Detailed checks")
        st.write("Ping output and DNS results for the targets you configured.")
        with st.expander("Ping details"):
            for item in [selected_ping] + default_ping:
                st.markdown(f"**{item['target']}** — {item['status']} — latency: {item['latency_ms']} ms")
                st.code(item["output"])
        with st.expander("DNS details"):
            for item in [selected_dns] + default_dns:
                st.markdown(f"**{item['target']}** — {item['status']}")
                if item["resolved"]:
                    st.write(", ".join(item["addresses"]))
                else:
                    st.error(item.get("error", "Lookup failed"))

    with tab2:
        st.subheader("Root Cause Analysis")
        rca_text = generate_rca(incident_df)
        st.text_area("RCA report", value=rca_text, height=320)
        st.download_button(
            "Download RCA report",
            rca_text,
            file_name="netops_rca_report.txt",
            mime="text/plain",
        )

    with tab3:
        st.subheader("Incident export")
        st.write("Download CSV logs for incident review and postmortem tracking.")
        csv_data = incident_df.to_csv(index=False)
        st.download_button(
            label="Export incident log as CSV",
            data=csv_data,
            file_name="incident_log.csv",
            mime="text/csv",
        )

        st.markdown("#### Service availability matrix")
        status_summary = pd.DataFrame(
            [
                {
                    "Target": item["target"],
                    "Reachable": item["reachable"],
                    "Latency (ms)": item["latency_ms"],
                }
                for item in [selected_ping] + default_ping
            ]
        )
        st.table(status_summary)


if __name__ == "__main__":
    main()
