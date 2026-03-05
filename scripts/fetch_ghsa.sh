#!/usr/bin/env bash
# 从 GitHub Advisory Database 拉取高危漏洞
#
# 用法:
#   bash fetch_ghsa.sh <ECOSYSTEM> [MIN_CVSS] [SEVERITIES]
#
# 参数:
#   ECOSYSTEM   — PIP / GO / NPM (必选)
#   MIN_CVSS    — 最低 CVSS 分数，默认 8
#   SEVERITIES  — 严重级别，默认 "CRITICAL, HIGH"
#
# 示例:
#   bash fetch_ghsa.sh PIP
#   bash fetch_ghsa.sh GO 9
#   bash fetch_ghsa.sh NPM 8 "CRITICAL"

set -euo pipefail

ECOSYSTEM="${1:?用法: bash fetch_ghsa.sh <PIP|GO|NPM> [MIN_CVSS] [SEVERITIES]}"
MIN_CVSS="${2:-8}"
SEVERITIES_RAW="${3:-CRITICAL, HIGH}"

# 将 "CRITICAL, HIGH" 转成 GraphQL 数组格式 [CRITICAL, HIGH]
SEVERITIES=$(echo "$SEVERITIES_RAW" | tr -d ' ' | sed 's/,/, /g')

QUERY=$(cat <<GRAPHQL
{
  securityVulnerabilities(
    first: 100,
    ecosystem: ${ECOSYSTEM},
    severities: [${SEVERITIES}],
    orderBy: {field: UPDATED_AT, direction: DESC}
  ) {
    nodes {
      advisory {
        ghsaId
        summary
        severity
        cvss { score vectorString }
        cwes(first: 5) { nodes { cweId name } }
        publishedAt
        references { url }
      }
      package { name }
      vulnerableVersionRange
      firstPatchedVersion { identifier }
    }
  }
}
GRAPHQL
)

gh api graphql -f query="$QUERY" | \
jq -r --argjson min_cvss "$MIN_CVSS" \
  '[.data.securityVulnerabilities.nodes[] | select(.advisory.cvss.score >= $min_cvss)]
   | unique_by(.advisory.ghsaId)
   | sort_by(-.advisory.cvss.score)
   | .[]
   | "\(.advisory.ghsaId) | CVSS \(.advisory.cvss.score) | \(.package.name) | \([.advisory.cwes.nodes[].cweId] | join(",")) | \(.advisory.summary)"'
