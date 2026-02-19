-- ============================================================================
-- SPCS Image Scanning Setup
-- Creates stage, tables, snowpipe, and views for vulnerability scanning
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Stage for scan results (mount this into the grype job)
-- ----------------------------------------------------------------------------
CREATE STAGE IF NOT EXISTS scan_results_stage
    DIRECTORY = (ENABLE = TRUE)
    COMMENT = 'Stage for grype scan result JSON files';

-- ----------------------------------------------------------------------------
-- Raw scan results table (stores entire grype JSON)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_results_raw (
    src         VARIANT,
    filename    STRING,
    ingested_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
);

-- ----------------------------------------------------------------------------
-- Snowpipe - loads raw JSON, no transformation
-- ----------------------------------------------------------------------------
CREATE PIPE IF NOT EXISTS scan_results_pipe
    AUTO_INGEST = TRUE
AS
COPY INTO scan_results_raw (src, filename)
FROM (
    SELECT $1, METADATA$FILENAME
    FROM @scan_results_stage
)
FILE_FORMAT = (TYPE = JSON);

-- ----------------------------------------------------------------------------
-- Dynamic table: flattens matches from raw JSON
-- ----------------------------------------------------------------------------
CREATE OR REPLACE DYNAMIC TABLE scan_results
    LAG = '1 minute'
    WAREHOUSE = <your_warehouse>
AS
SELECT
    -- Source metadata (strip registry URL prefix)
    REGEXP_REPLACE(
        src:source:target:userInput::STRING,
        '^[^/]+\\.registry(-local)?\\.snowflakecomputing\\.com/',
        ''
    ) AS image_tag,
    src:source:target:imageID::STRING AS image_id,
    src:source:target:manifestDigest::STRING AS manifest_digest,
    src:distro:name::STRING AS distro_name,
    src:distro:version::STRING AS distro_version,
    -- Vulnerability
    m.value:vulnerability:id::STRING AS cve_id,
    m.value:vulnerability:severity::STRING AS severity,
    m.value:vulnerability:description::STRING AS description,
    m.value:vulnerability:risk::FLOAT AS risk_score,
    -- EPSS
    m.value:vulnerability:epss[0]:epss::FLOAT AS epss_score,
    m.value:vulnerability:epss[0]:percentile::FLOAT AS epss_percentile,
    -- KEV
    m.value:vulnerability:kev IS NOT NULL AS is_kev,
    -- CVSS
    m.value:vulnerability:cvss[0]:metrics:baseScore::FLOAT AS cvss_score,
    m.value:vulnerability:cvss[0]:vector::STRING AS cvss_vector,
    -- Fix
    m.value:vulnerability:fix:state::STRING AS fix_state,
    m.value:vulnerability:fix:versions[0]::STRING AS fixed_version,
    -- Package
    m.value:artifact:name::STRING AS package_name,
    m.value:artifact:version::STRING AS package_version,
    m.value:artifact:type::STRING AS package_type,
    m.value:artifact:purl::STRING AS package_purl,
    -- Metadata
    filename,
    ingested_at
FROM scan_results_raw,
LATERAL FLATTEN(input => src:matches) m;

-- ----------------------------------------------------------------------------
-- Asset inventory for business context enrichment
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS asset_inventory (
    image_pattern   STRING,
    environment     STRING,
    owning_team     STRING,
    criticality     STRING
);

-- Sample data
INSERT INTO asset_inventory VALUES
    ('%python:3.6%', 'dev', 'data-platform', 'tier-3'),
    ('%postgis%', 'prod', 'geospatial', 'tier-1');

-- ----------------------------------------------------------------------------
-- Enriched view with asset context
-- ----------------------------------------------------------------------------
CREATE OR REPLACE VIEW scan_results_enriched AS
SELECT
    s.*,
    a.environment,
    a.owning_team,
    a.criticality,
    -- Priority: KEV > high EPSS > severity
    CASE
        WHEN s.is_kev THEN 100
        WHEN s.risk_score >= 80 THEN s.risk_score
        WHEN s.epss_score >= 0.1 THEN 90
        WHEN s.severity = 'Critical' THEN 80
        WHEN s.severity = 'High' THEN 60
        ELSE 40
    END AS priority_score
FROM scan_results s
LEFT JOIN asset_inventory a ON s.image_tag LIKE a.image_pattern;
