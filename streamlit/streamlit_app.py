"""
SPCS Image Vulnerability Scanner Dashboard
Displays scan results with EPSS, KEV, and asset context enrichment
"""

import streamlit as st
from snowflake.snowpark.context import get_active_session

st.set_page_config(
    page_title="SPCS Image Scanner",
    layout="wide"
)

session = get_active_session()


def get_scan_summary():
    """Get summary of all scanned images."""
    return session.sql("""
        SELECT
            s.image_tag,
            s.distro_name,
            s.distro_version,
            MAX(s.ingested_at) AS last_scanned,
            COUNT(DISTINCT s.cve_id) AS total_cves,
            COUNT(DISTINCT CASE WHEN s.severity = 'Critical' THEN s.cve_id END) AS critical_count,
            COUNT(DISTINCT CASE WHEN s.severity = 'High' THEN s.cve_id END) AS high_count,
            COUNT(DISTINCT CASE WHEN s.is_kev THEN s.cve_id END) AS kev_count,
            COUNT(DISTINCT CASE WHEN s.fix_state = 'fixed' THEN s.cve_id END) AS fixable_count,
            ROUND(AVG(s.risk_score), 2) AS avg_risk_score,
            MAX(s.priority_score) AS max_priority,
            MAX(s.environment) AS environment,
            MAX(s.owning_team) AS owning_team,
            MAX(s.criticality) AS criticality
        FROM scan_results_enriched s
        GROUP BY s.image_tag, s.distro_name, s.distro_version
        ORDER BY max_priority DESC, last_scanned DESC
    """).to_pandas()


def get_vulnerabilities(
    image_tag: str = None,
    min_priority: int = 0,
    environment: str = None,
    team: str = None
):
    """Get enriched vulnerability data with asset context."""
    query = """
        SELECT 
            cve_id,
            severity,
            package_name,
            package_version,
            fixed_version,
            fix_state,
            ROUND(risk_score, 2) AS risk_score,
            ROUND(epss_score, 4) AS epss_score,
            ROUND(epss_percentile, 2) AS epss_percentile,
            is_kev,
            ROUND(cvss_score, 1) AS cvss_score,
            priority_score,
            fix_state = 'fixed' AS has_fix,
            image_tag,
            distro_name || ':' || distro_version AS distro,
            ingested_at,
            environment,
            owning_team,
            criticality,
            description
        FROM scan_results_enriched
        WHERE priority_score >= ?
    """
    params = [min_priority]
    
    if image_tag:
        query += " AND image_tag = ?"
        params.append(image_tag)
    
    if environment:
        query += " AND environment = ?"
        params.append(environment)
    
    if team:
        query += " AND owning_team = ?"
        params.append(team)
    
    query += " ORDER BY priority_score DESC, epss_score DESC NULLS LAST"
    
    return session.sql(query, params=params).to_pandas()


def get_filter_options():
    """Get distinct values for filters."""
    images = session.sql(
        "SELECT DISTINCT image_tag FROM scan_results ORDER BY image_tag"
    ).to_pandas()["IMAGE_TAG"].tolist()
    
    envs = session.sql(
        "SELECT DISTINCT environment FROM asset_inventory WHERE environment IS NOT NULL ORDER BY environment"
    ).to_pandas()["ENVIRONMENT"].tolist()
    
    teams = session.sql(
        "SELECT DISTINCT owning_team FROM asset_inventory WHERE owning_team IS NOT NULL ORDER BY owning_team"
    ).to_pandas()["OWNING_TEAM"].tolist()
    
    return images, envs, teams


st.title("SPCS Image Vulnerability Scanner")

images, environments, teams = get_filter_options()

with st.sidebar:
    st.header("Filters")
    
    selected_image = st.selectbox(
        "Image",
        options=["All Images"] + images,
        index=0
    )
    
    selected_env = st.selectbox(
        "Environment",
        options=["All"] + environments,
        index=0
    )
    
    selected_team = st.selectbox(
        "Team",
        options=["All"] + teams,
        index=0
    )
    
    min_priority = st.slider(
        "Minimum Priority",
        min_value=0,
        max_value=100,
        value=0,
        help="KEV=100, High Risk=80+, Critical=80, High=60"
    )
    
    show_kev_only = st.checkbox("KEV only", value=False)
    show_fixable_only = st.checkbox("Fixable only", value=False)

# Navigation
view = st.segmented_control(
    "View",
    options=["Overview", "Vulnerabilities", "Analysis"],
    default="Overview"
)

if view == "Overview":
    summary_df = get_scan_summary()
    
    if summary_df.empty:
        st.info("No scan results yet. Run a scan job to see data here.")
    else:
        col1, col2, col3, col4 = st.columns(4)
        
        total_images = len(summary_df)
        total_cves = int(summary_df["TOTAL_CVES"].sum())
        total_critical = int(summary_df["CRITICAL_COUNT"].sum())
        total_kev = int(summary_df["KEV_COUNT"].sum())
        
        col1.metric("Images", total_images)
        col2.metric("Total CVEs", total_cves)
        col3.metric("Critical", total_critical)
        col4.metric("KEV", total_kev)
        
        st.subheader("Images by Risk")
        st.dataframe(
            summary_df,
            column_config={
                "IMAGE_TAG": st.column_config.TextColumn("Image", width="medium"),
                "DISTRO_NAME": st.column_config.TextColumn("Distro"),
                "DISTRO_VERSION": st.column_config.TextColumn("Ver"),
                "ENVIRONMENT": st.column_config.TextColumn("Env"),
                "OWNING_TEAM": st.column_config.TextColumn("Team"),
                "CRITICALITY": st.column_config.TextColumn("Tier"),
                "TOTAL_CVES": st.column_config.NumberColumn("CVEs"),
                "CRITICAL_COUNT": st.column_config.NumberColumn("Crit"),
                "HIGH_COUNT": st.column_config.NumberColumn("High"),
                "KEV_COUNT": st.column_config.NumberColumn("KEV"),
                "FIXABLE_COUNT": st.column_config.NumberColumn("Fixable"),
                "AVG_RISK_SCORE": st.column_config.NumberColumn("Avg Risk", format="%.1f"),
                "MAX_PRIORITY": st.column_config.ProgressColumn("Priority", min_value=0, max_value=100, format="%.0f"),
            },
            column_order=[
                "IMAGE_TAG", "ENVIRONMENT", "OWNING_TEAM", "CRITICALITY",
                "TOTAL_CVES", "CRITICAL_COUNT", "HIGH_COUNT", "KEV_COUNT", "FIXABLE_COUNT",
                "AVG_RISK_SCORE", "MAX_PRIORITY"
            ],
            hide_index=True,
            use_container_width=True
        )

elif view == "Vulnerabilities":
    image_filter = None if selected_image == "All Images" else selected_image
    env_filter = None if selected_env == "All" else selected_env
    team_filter = None if selected_team == "All" else selected_team
    
    vulns_df = get_vulnerabilities(image_filter, min_priority, env_filter, team_filter)
    
    if show_kev_only and not vulns_df.empty:
        vulns_df = vulns_df[vulns_df["IS_KEV"] == True]
    
    if show_fixable_only and not vulns_df.empty:
        vulns_df = vulns_df[vulns_df["HAS_FIX"] == True]
    
    if vulns_df.empty:
        st.info("No vulnerabilities match the current filters.")
    else:
        kev_count = len(vulns_df[vulns_df["IS_KEV"] == True])
        if kev_count > 0:
            st.warning(f"{kev_count} Known Exploited Vulnerabilities (KEV) in results")
        
        st.subheader(f"Vulnerabilities ({len(vulns_df)})")
        st.dataframe(
            vulns_df,
            column_config={
                "CVE_ID": st.column_config.TextColumn("CVE"),
                "SEVERITY": st.column_config.TextColumn("Sev"),
                "PACKAGE_NAME": st.column_config.TextColumn("Package"),
                "PACKAGE_VERSION": st.column_config.TextColumn("Version"),
                "FIXED_VERSION": st.column_config.TextColumn("Fix In"),
                "RISK_SCORE": st.column_config.NumberColumn("Risk", format="%.1f"),
                "EPSS_SCORE": st.column_config.NumberColumn("EPSS", format="%.4f"),
                "IS_KEV": st.column_config.CheckboxColumn("KEV"),
                "CVSS_SCORE": st.column_config.NumberColumn("CVSS", format="%.1f"),
                "PRIORITY_SCORE": st.column_config.ProgressColumn("Priority", min_value=0, max_value=100, format="%.0f"),
                "HAS_FIX": st.column_config.CheckboxColumn("Fix?"),
                "IMAGE_TAG": st.column_config.TextColumn("Image"),
                "ENVIRONMENT": st.column_config.TextColumn("Env"),
                "OWNING_TEAM": st.column_config.TextColumn("Team"),
                "DESCRIPTION": st.column_config.TextColumn("Description", width="large"),
            },
            column_order=[
                "CVE_ID", "SEVERITY", "PACKAGE_NAME", "PACKAGE_VERSION", "FIXED_VERSION",
                "RISK_SCORE", "EPSS_SCORE", "IS_KEV", "PRIORITY_SCORE", "HAS_FIX",
                "IMAGE_TAG", "ENVIRONMENT", "OWNING_TEAM"
            ],
            hide_index=True,
            use_container_width=True
        )

elif view == "Analysis":
    all_vulns = get_vulnerabilities(min_priority=0)
    
    if all_vulns.empty:
        st.info("No data available for analysis.")
    else:
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("By Severity")
            severity_counts = all_vulns["SEVERITY"].value_counts()
            st.bar_chart(severity_counts)
        
        with col2:
            st.subheader("By Environment")
            env_counts = all_vulns["ENVIRONMENT"].value_counts()
            st.bar_chart(env_counts)
        
        col3, col4 = st.columns(2)
        
        with col3:
            st.subheader("By Team")
            team_counts = all_vulns["OWNING_TEAM"].value_counts()
            st.bar_chart(team_counts)
        
        with col4:
            st.subheader("Fix Availability")
            fix_counts = all_vulns["FIX_STATE"].value_counts()
            st.bar_chart(fix_counts)
        
        st.subheader("Recommended Remediations")
        st.caption("High priority vulnerabilities with available fixes")
        quick_wins = all_vulns[
            (all_vulns["HAS_FIX"] == True) & 
            (all_vulns["PRIORITY_SCORE"] >= 60)
        ].sort_values("PRIORITY_SCORE", ascending=False).head(15)
        
        if not quick_wins.empty:
            st.dataframe(
                quick_wins[[
                    "CVE_ID", "SEVERITY", "PACKAGE_NAME", "FIXED_VERSION",
                    "IMAGE_TAG", "ENVIRONMENT", "PRIORITY_SCORE"
                ]],
                hide_index=True,
                use_container_width=True
            )
        else:
            st.info("No high-priority fixable vulnerabilities found.")

st.divider()
st.caption("Data: grype scanner | Enrichment: EPSS, KEV, Asset Inventory")
