import sys
import subprocess
import requests
import streamlit as st
import pandas as pd
import plotly.express as px
from models import SessionLocal, IOC, Vulnerability

# 1. Page Configuration
st.set_page_config(
    page_title="SPECTRE // Cyber Threat Intelligence",
    page_icon="⚡",
    layout="wide",
    initial_sidebar_state="expanded"
)

# 2. Modern SOC / Glassmorphic CSS Styling
CUSTOM_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Plus+Jakarta+Sans:wght@400;600;700;800&display=swap');

html, body, [class*="css"] {
    font-family: 'Plus Jakarta Sans', sans-serif;
}

code, pre, .mono-font {
    font-family: 'JetBrains Mono', monospace !important;
}

.stApp {
    background: radial-gradient(circle at 10% 10%, #0d1527 0%, #060911 90%) !important;
}

.soc-card {
    background: rgba(13, 22, 38, 0.7);
    border: 1px solid rgba(0, 240, 255, 0.15);
    border-radius: 12px;
    padding: 18px 22px;
    box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
    backdrop-filter: blur(8px);
    transition: transform 0.2s ease, border-color 0.2s ease;
}
.soc-card:hover {
    transform: translateY(-2px);
    border-color: rgba(0, 240, 255, 0.45);
}
.soc-title {
    font-size: 0.78rem;
    font-weight: 700;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: #94a3b8;
    margin-bottom: 6px;
}
.soc-value {
    font-size: 2.1rem;
    font-weight: 800;
    font-family: 'JetBrains Mono', monospace;
    color: #f8fafc;
    letter-spacing: -0.02em;
}
.soc-sub {
    font-size: 0.75rem;
    margin-top: 4px;
    font-weight: 600;
}
.neon-cyan { color: #00f0ff; text-shadow: 0 0 12px rgba(0, 240, 255, 0.4); }
.neon-red { color: #ff3366; text-shadow: 0 0 12px rgba(255, 51, 102, 0.4); }
.neon-amber { color: #ffaa00; text-shadow: 0 0 12px rgba(255, 170, 0, 0.4); }
.neon-purple { color: #bd00ff; text-shadow: 0 0 12px rgba(189, 0, 255, 0.4); }

.pulse-container {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 0.85rem;
    font-weight: 600;
    color: #00f0ff;
    letter-spacing: 0.05em;
}
.pulse-dot {
    width: 9px;
    height: 9px;
    background-color: #00f0ff;
    border-radius: 50%;
    box-shadow: 0 0 0 rgba(0, 240, 255, 0.7);
    animation: pulse 1.8s infinite;
}
@keyframes pulse {
    0% { box-shadow: 0 0 0 0 rgba(0, 240, 255, 0.7); }
    70% { box-shadow: 0 0 0 8px rgba(0, 240, 255, 0); }
    100% { box-shadow: 0 0 0 0 rgba(0, 240, 255, 0); }
}

button[data-baseweb="tab"] {
    background: transparent !important;
    border-radius: 8px !important;
    padding: 8px 18px !important;
    font-weight: 600 !important;
    color: #94a3b8 !important;
}
button[data-baseweb="tab"][aria-selected="true"] {
    color: #00f0ff !important;
    background: rgba(0, 240, 255, 0.08) !important;
    border: 1px solid rgba(0, 240, 255, 0.25) !important;
}
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# 3. Top Header Bar
col_h1, col_h2 = st.columns([3, 1])
with col_h1:
    st.markdown("## ⚡ SPECTRE // Threat Intelligence Platform")
    st.caption("TACTICAL LEVEL 3 CORRELATION ENGINE • C2 TRACKING • ACTIVE EXPLOIT INTEL")
with col_h2:
    st.markdown("""
        <div style="text-align: right; padding-top: 10px;">
            <div class="pulse-container" style="justify-content: flex-end;">
                <div class="pulse-dot"></div>
                TELEMETRY LIVE
            </div>
            <div style="font-size: 0.75rem; color: #64748b; font-family: 'JetBrains Mono';">HOST: macOS ARM64</div>
        </div>
    """, unsafe_allow_html=True)

st.markdown("<hr style='border: 0; height: 1px; background: rgba(0, 240, 255, 0.15); margin: 10px 0 24px 0;'>", unsafe_allow_html=True)

# 4. Sidebar Controls
with st.sidebar:
    st.markdown("### 🎛️ Operation Controls")
    if st.button("⚡ FORCE FEED RE-SYNC", type="primary", use_container_width=True):
        with st.spinner("Executing intelligence acquisition pipeline..."):
            result = subprocess.run([sys.executable, "ingest.py"], capture_output=True, text=True)
            if result.returncode == 0:
                st.success("Ingestion pipeline finished cleanly!")
                with st.expander("Telemetry logs"):
                    st.code(result.stdout)
            else:
                st.error("Ingestion failed")
                st.code(result.stderr)

    st.markdown("---")
    st.markdown("""
        **Pipeline Feeds:**
        - `Abuse.ch Feodo` (C2 IP Nodes)
        - `URLhaus` (Payload Distributors)
        - `CISA KEV` (Active Zero-Days)
        
        **Node Architecture:**
        - Apple Silicon M1 Native
        - SQLite Memory-Optimized
    """)

# 5. Load Data
@st.cache_data(ttl=60)
def load_threat_data():
    session = SessionLocal()
    try:
        iocs_df = pd.read_sql(session.query(IOC).statement, session.bind)
        vulns_df = pd.read_sql(session.query(Vulnerability).statement, session.bind)
    finally:
        session.close()
    return iocs_df, vulns_df

iocs_df, vulns_df = load_threat_data()

# 6. KPI Telemetry Cards
total_iocs = len(iocs_df)
c2_count = len(iocs_df[iocs_df['threat_type'] == 'botnet_c2']) if total_iocs > 0 else 0
total_vulns = len(vulns_df)
unique_countries = iocs_df['country'].dropna().nunique() if total_iocs > 0 else 0

m1, m2, m3, m4 = st.columns(4)
with m1:
    st.markdown(f"""
        <div class="soc-card">
            <div class="soc-title">Active Observables</div>
            <div class="soc-value neon-cyan">{total_iocs:,}</div>
            <div class="soc-sub neon-cyan">↑ Indexed & normalized</div>
        </div>
    """, unsafe_allow_html=True)
with m2:
    st.markdown(f"""
        <div class="soc-card">
            <div class="soc-title">Botnet C2 Nodes</div>
            <div class="soc-value neon-red">{c2_count:,}</div>
            <div class="soc-sub neon-red">Critical Severity (Feodo)</div>
        </div>
    """, unsafe_allow_html=True)
with m3:
    st.markdown(f"""
        <div class="soc-card">
            <div class="soc-title">Threat Geographic Reach</div>
            <div class="soc-value neon-amber">{unique_countries}</div>
            <div class="soc-sub neon-amber">Target/Origin Nations</div>
        </div>
    """, unsafe_allow_html=True)
with m4:
    st.markdown(f"""
        <div class="soc-card">
            <div class="soc-title">Exploited CVEs (KEV)</div>
            <div class="soc-value neon-purple">{total_vulns:,}</div>
            <div class="soc-sub neon-purple">CISA Known Catalog</div>
        </div>
    """, unsafe_allow_html=True)

st.markdown("<div style='margin-bottom: 24px;'></div>", unsafe_allow_html=True)

# 7. Main Dashboard Tabs
tab_map, tab_analytics, tab_vulns, tab_triage = st.tabs([
    "🌍 Global Threat Vectors",
    "📊 Threat Matrix & IOCs",
    "🛡️ Active CVE Radar",
    "🔍 Fast Forensics Lookup"
])

DARK_LAYOUT = dict(
    paper_bgcolor='rgba(13, 22, 38, 0.4)',
    plot_bgcolor='rgba(13, 22, 38, 0.4)',
    font=dict(family="Plus Jakarta Sans", color="#94a3b8"),
    margin=dict(l=20, r=20, t=40, b=20)
)

# Tab 1: Global Map
with tab_map:
    geo_df = iocs_df.dropna(subset=['latitude', 'longitude'])
    if not geo_df.empty:
        fig_map = px.scatter_geo(
            geo_df,
            lat="latitude",
            lon="longitude",
            hover_name="value",
            hover_data={"country": True, "description": True, "threat_type": True, "latitude": False, "longitude": False},
            color_discrete_sequence=["#00f0ff"],
            projection="natural earth",
            title="Global Coordinates of Malicious C2 Infrastructure"
        )
        fig_map.update_geos(
            showcountries=True,
            countrycolor="#1e293b",
            showocean=True,
            oceancolor="#070b14",
            showland=True,
            landcolor="#0d1527",
            bgcolor="#060911"
        )
        fig_map.update_traces(marker=dict(size=7, opacity=0.85, line=dict(width=1, color="#ffffff")))
        fig_map.update_layout(**DARK_LAYOUT, height=520)
        st.plotly_chart(fig_map, use_container_width=True)

        col_g1, col_g2 = st.columns(2)
        with col_g1:
            st.markdown("#### Top Origin / Host Countries")
            country_dist = geo_df['country'].value_counts().head(6).reset_index()
            country_dist.columns = ['Country', 'Identified Hosts']
            st.dataframe(country_dist, use_container_width=True)
        with col_g2:
            st.markdown("#### Live C2 Signals")
            st.dataframe(geo_df[['value', 'country', 'description', 'first_seen']].head(6), use_container_width=True)
    else:
        st.info("No geographical records available. Use sidebar to sync.")

# Tab 2: Threat Matrix & IOCs
with tab_analytics:
    if not iocs_df.empty:
        c1, c2 = st.columns(2)
        with c1:
            fig_types = px.pie(
                iocs_df, 
                names="threat_type", 
                title="Observable Threat Taxonomy",
                hole=0.6,
                color_discrete_sequence=['#00f0ff', '#ff3366', '#ffaa00', '#bd00ff', '#00e676']
            )
            fig_types.update_layout(**DARK_LAYOUT)
            st.plotly_chart(fig_types, use_container_width=True)

        with c2:
            fig_conf = px.histogram(
                iocs_df,
                x="confidence_score",
                nbins=12,
                title="Confidence Score Reliability Profile",
                color_discrete_sequence=['#ff3366']
            )
            fig_conf.update_layout(**DARK_LAYOUT)
            st.plotly_chart(fig_conf, use_container_width=True)

        st.markdown("#### Ingested IOC Registry")
        st.dataframe(
            iocs_df[["value", "ioc_type", "threat_type", "confidence_score", "source", "country", "first_seen"]],
            use_container_width=True,
            height=300
        )

# Tab 3: CVE Radar
with tab_vulns:
    if not vulns_df.empty:
        vendor_counts = vulns_df["vendor_project"].value_counts().head(8).reset_index()
        vendor_counts.columns = ["Vendor", "Exploited Vulnerabilities"]
        
        fig_vendors = px.bar(
            vendor_counts,
            x="Vendor",
            y="Exploited Vulnerabilities",
            title="Top Vendors Under Active Weaponized Exploitation",
            color="Exploited Vulnerabilities",
            color_continuous_scale=[[0, '#00f0ff'], [1, '#ff3366']]
        )
        fig_vendors.update_layout(**DARK_LAYOUT)
        st.plotly_chart(fig_vendors, use_container_width=True)

        st.markdown("#### Exploited Vulnerabilities Database")
        st.dataframe(
            vulns_df[["cve_id", "vendor_project", "product", "vulnerability_name", "date_added"]],
            use_container_width=True,
            height=300
        )

# Tab 4: Fast Forensics Lookup (with Live External Fallback)
with tab_triage:
    st.markdown("#### Observables Triage Engine")
    search_q = st.text_input("Investigate IP, Hash, Domain, or CVE ID:", placeholder="e.g. 185., CVE-2024, http...")
    
    if search_q:
        m_iocs = iocs_df[iocs_df["value"].str.contains(search_q, case=False, na=False)]
        m_cves = vulns_df[vulns_df["cve_id"].str.contains(search_q, case=False, na=False) | vulns_df["product"].str.contains(search_q, case=False, na=False)]
        
        if not m_iocs.empty:
            st.success(f"Matched {len(m_iocs)} Local Indicator record(s)")
            st.dataframe(m_iocs[['value', 'ioc_type', 'threat_type', 'country', 'confidence_score', 'description']], use_container_width=True)
        elif not m_cves.empty:
            st.success(f"Matched {len(m_cves)} Vulnerability record(s)")
            st.dataframe(m_cves[['cve_id', 'vendor_project', 'product', 'vulnerability_name']], use_container_width=True)
        else:
            with st.spinner("Checking live external intelligence on URLhaus API..."):
                try:
                    api_res = requests.post(
                        "https://urlhaus-api.abuse.ch/v1/url/",
                        data={"url": search_q},
                        timeout=5
                    ).json()
                    
                    if api_res.get("query_status") == "ok":
                        st.warning("⚠️ Indicator identified via live external feed:")
                        st.json({
                            "URL": api_res.get("url"),
                            "Threat": api_res.get("threat"),
                            "Status": api_res.get("url_status"),
                            "Reporter": api_res.get("reporter"),
                            "Tags": api_res.get("tags")
                        })
                    else:
                        st.info(f"No intelligence correlates found locally or externally for '{search_q}'.")
                except Exception:
                    st.info(f"No intelligence correlates found locally for '{search_q}'.")
