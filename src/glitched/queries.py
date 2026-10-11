"""Domain-specific read queries over the threat-intel tables (see db.py)."""

from __future__ import annotations

import re
from typing import Any

from glitched.catalog import PLATFORMS, PRODUCT_ALIASES, ROS_CORE, ROS_DISTROS, ROS_VENDORS
from glitched.db import DATABASE_URL, query

KNOWN_EXPLOITABLE_WEAKNESS = "known exploitable weakness"


def get_known_exploitable_vulnerabilities() -> list[dict[str, Any]]:
    """EMB3D threats with maturity = 'known exploitable weakness'."""
    return query(
        "SELECT * FROM emb3d_threats WHERE maturity = %s AND is_current ORDER BY id",
        [KNOWN_EXPLOITABLE_WEAKNESS],
    )


def get_known_exploitable_by_category() -> list[dict[str, Any]]:
    """Count of known-exploitable-weakness threats per device category."""
    return query(
        """
        SELECT category, count(*) AS threat_count
        FROM emb3d_threats
        WHERE maturity = %s AND is_current
        GROUP BY category
        ORDER BY threat_count DESC
        """,
        [KNOWN_EXPLOITABLE_WEAKNESS],
    )


def get_mitigation_depth_by_category() -> list[dict[str, Any]]:
    """
    Average number of documented mitigations per threat, by category, across
    the full EMB3D catalogue (not just known-exploitable-weakness threats).
    Compare against get_known_exploitable_mitigation_depth() to see whether a
    category's defense-in-depth pattern holds catalogue-wide or is an
    artifact of the smaller known-exploitable slice.
    """
    return query(
        """
        SELECT t.category, avg(m.mitigation_count) AS avg_mitigations
        FROM emb3d_threats t
        JOIN (
            SELECT threat_id, count(*) AS mitigation_count
            FROM emb3d_mitigation_threats
            WHERE is_current
            GROUP BY threat_id
        ) m ON m.threat_id = t.id
        WHERE t.is_current
        GROUP BY t.category
        ORDER BY avg_mitigations
        """
    )


def get_known_exploitable_mitigation_depth() -> list[dict[str, Any]]:
    """
    Average number of documented mitigations per known-exploitable-weakness
    threat, by category. Low depth in a high-count category is the signal
    worth acting on: many confirmed-exploitable threats, few independent
    defenses against them.
    """
    return query(
        """
        SELECT t.category, avg(m.mitigation_count) AS avg_mitigations
        FROM emb3d_threats t
        JOIN (
            SELECT threat_id, count(*) AS mitigation_count
            FROM emb3d_mitigation_threats
            WHERE is_current
            GROUP BY threat_id
        ) m ON m.threat_id = t.id
        WHERE t.maturity = %s AND t.is_current
        GROUP BY t.category
        ORDER BY avg_mitigations
        """,
        [KNOWN_EXPLOITABLE_WEAKNESS],
    )


# --------------------------------------------------------------------------
# Exposure: which threats and CVEs affect a device profile
# --------------------------------------------------------------------------

# EMB3D threats exposed by a set of device properties, with the properties that
# linked them. Shared with assess._plan_threats so scoping an assessment and
# reporting exposure agree on what applies.
THREATS_FOR_PROPERTIES_SQL = """
    SELECT t.id, t.name, t.maturity, t.cve_ids,
           array_agg(DISTINCT p.name ORDER BY p.name) AS via
    FROM emb3d_property_threats pt
    JOIN emb3d_threats t ON t.id = pt.threat_id
    JOIN emb3d_properties p ON p.id = pt.property_id
    WHERE pt.property_id = ANY(%s) AND pt.is_current AND t.is_current
    GROUP BY t.id, t.name, t.maturity, t.cve_ids
    ORDER BY t.id
"""

# Lower sorts first. Real platform CVEs beat taxonomy threats.
_EMB3D_RANK = {
    KNOWN_EXPLOITABLE_WEAKNESS: 1,
    "observed adversarial technique": 2,
    "observed adversarial behavior": 2,
    "proof of concept": 3,
}


def tables_exist(tables: list[str], database_url: str = DATABASE_URL) -> bool:
    """True if every table exists - optional sources (papers, NVD, curated notes) may not."""
    rows = query("SELECT bool_and(to_regclass(t) IS NOT NULL) AS ok FROM unnest(%s::text[]) AS t",
                 [tables], database_url=database_url)
    return bool(rows[0]["ok"])


# Tables each optional part of the exposure report needs.
PAPER_TABLES = ["research_papers", "research_paper_emb3d_threats", "research_paper_atlas_techniques",
                "research_paper_checks", "emb3d_property_threats"]


def get_exposure(
    tags: list[str],
    property_ids: list[str],
    ml: bool,
    database_url: str = DATABASE_URL,
    components: list[tuple[str, str | None]] = (),
    ros_distro: str | None = None,
) -> list[dict[str, Any]]:
    """
    Everything in the threat-intel tables that applies to a device profile,
    most urgent first. Each row: source, ref_id, title, severity, reason, rank,
    related.

    CVEs apply through a platform the device is built on or an SBOM component
    (name, version) that NVD lists as affected. ROS is an ecosystem, not one
    product: core ROS CVEs apply by the robot's ROS distro, package CVEs only
    through the SBOM. CVEs that only share a keyword (wifi, mqtt, "ros") are
    about other products: they come back with related=True for the caller to
    hide or show separately.
    """
    rows = _cve_exposure(set(tags), list(components), database_url, ros_distro)
    if property_ids:
        rows += _emb3d_exposure(property_ids, database_url)
    if ml:
        rows += _atlas_exposure(database_url)
    rows += _paper_exposure(tags, property_ids, ml, database_url)
    for row in rows:
        row.setdefault("related", False)
    return sorted(rows, key=lambda r: (r["rank"], r["source"], r["ref_id"]))


def component_parts(label: str) -> tuple[str, str | None]:
    """"mosquitto 1.4.10" -> ("mosquitto", "1.4.10")."""
    name, _, version = label.partition(" ")
    return name, version or None


def _norm(name: str) -> str:
    """Compare package and CPE product names loosely: paho-mqtt == paho_mqtt == Paho.MQTT."""
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


def _version_key(version: str) -> tuple:
    """1.4.12 -> (1, 4, 12); letters sort before numbers so 2.0rc1 < 2.0.1."""
    return tuple((1, int(part)) if part.isdigit() else (0, part)
                 for part in re.findall(r"\d+|[a-z]+", version.lower()))


def version_affected(version: str, product: dict) -> bool:
    """Is `version` inside the affected range of one nvd_affected_products row?"""
    if product.get("version"):
        return _version_key(version) == _version_key(product["version"])
    key = _version_key(version)
    if (v := product.get("version_start_including")) and key < _version_key(v):
        return False
    if (v := product.get("version_start_excluding")) and key <= _version_key(v):
        return False
    if (v := product.get("version_end_including")) and key > _version_key(v):
        return False
    if (v := product.get("version_end_excluding")) and key >= _version_key(v):
        return False
    return True  # inside the bounds, or NVD says every version


def component_keys(name: str) -> set[str]:
    """
    Names an SBOM component may match an NVD product by: its own, without a
    ROS Debian prefix (ros-humble-navigation2 -> navigation2), and the NVD
    product it's an alias of (navigation2 -> nav2).
    """
    key = _norm(name)
    keys = {key}
    match = re.match(r"^ros_([a-z]+)_(.+)$", key)
    if match and match.group(1) in ROS_DISTROS:
        keys.add(match.group(2))
    for product, aliases in PRODUCT_ALIASES.items():
        names = {_norm(a) for a in aliases}
        # Exact aliases, or a family's packages (nav2_planner, moveit_core, ...).
        if keys & names or any(k.startswith(f"{_norm(product)}_") for k in keys):
            keys.add(_norm(product))
    return keys


def _product_key(product: dict) -> str:
    return _norm(product.get("product") or "")


def component_match(products: list[dict], components: list[tuple[str, str | None]]) -> tuple[str, str] | None:
    """
    Does any SBOM component appear among a CVE's affected products
    (nvd_affected_products rows)? Returns (component label, verdict):
    "affected" when its version is in an affected range, "unchecked" when the
    SBOM gives no version or the ranges aren't loaded, "not_affected" when its
    version is outside every affected range - or None if no component appears.
    """
    by_name = {key: (name, version) for name, version in components for key in component_keys(name)}
    found = None
    for product in products:
        if (key := _product_key(product)) not in by_name:
            continue
        name, version = by_name[key]
        if not version or product.get("unranged"):
            found = (name + (f" {version}" if version else ""), "unchecked")
        elif version_affected(version, product):
            return f"{name} {version}", "affected"
        elif not found:
            found = (f"{name} {version}", "not_affected")
    return found


def fixed_version(products: list[dict], name: str, version: str | None) -> str | None:
    """The first version outside the affected range that includes `version` (NVD's versionEnd*), if known."""
    for product in products:
        if _product_key(product) not in component_keys(name) or product.get("unranged"):
            continue
        if version and not version_affected(version, product):
            continue
        if product.get("version_end_excluding"):
            return product["version_end_excluding"]
        if product.get("version_end_including"):
            return f"newer than {product['version_end_including']}"
    return None


def summary(description: str, limit: int = 96) -> str:
    """A short plain title from a CVE description: its first sentence, cut at a word."""
    text = " ".join((description or "").split())
    sentences = re.split(r"(?<=[a-z0-9)])\. ", text)
    first = sentences[0]
    # GitHub-style advisories open with what the product is ("X is a ... framework"); skip that.
    if len(sentences) > 1 and re.match(r"^[\w.@/+-]+ is an? ", first):
        first = sentences[1]
    first = first.rstrip(". ")
    if len(first) <= limit:
        return first
    return first[:limit].rsplit(" ", 1)[0].rstrip(",;:") + "…"


def _affected_products(database_url: str) -> dict[str, list[dict]]:
    """CVE id -> the products NVD marks vulnerable, with version ranges."""
    if tables_exist(["nvd_affected_products"], database_url):
        rows = query("SELECT * FROM nvd_affected_products", database_url=database_url)
    else:  # a warehouse built before the table existed: names only, no ranges
        rows = [{"cve_id": r["id"], "product": cpe.split(":")[4] if cpe.count(":") > 4 else None,
                 "version": None, "unranged": True}
                for r in query("SELECT id, affected_cpes FROM nvd_cves", database_url=database_url)
                for cpe in r["affected_cpes"] or []]
    by_cve: dict[str, list[dict]] = {}
    for row in rows:
        by_cve.setdefault(row["cve_id"], []).append(row)
    return by_cve


# Package names that, in a description, mean a CVE is about that package even
# when NVD files it under core ROS (e.g. "ROS2 navigation2 v.humble").
_ROS_PACKAGE_MENTION = re.compile(r"\b(navigation2|nav2|moveit|rosbridge|roslibjs|ntpd_driver)\b", re.I)


def ros_match(products: list[dict], distro: str | None, description: str = "") -> tuple[str, str] | None:
    """
    For an NVD CVE that mentions ROS and nothing the SBOM confirms: does it
    apply to a robot on `distro`? Returns ("applies", reason), ("related",
    reason), or None when it's core ROS for another generation or distro.
    """
    core = [p for p in products if (p.get("vendor"), p.get("product")) in ROS_CORE]
    package = _ROS_PACKAGE_MENTION.search(description or "")
    if core and package:
        # Filed under core ROS but about one package: needs the package in the SBOM.
        return "related", f"in the ROS package {package.group(1).lower()} - list it in an SBOM to check"
    if core:
        if not distro:
            return "related", "affects core ROS - set the robot's ROS distro to check"
        generation = ROS_DISTROS[distro]
        for p in core:
            fixed_generation = ROS_CORE[(p["vendor"], p["product"])]
            version = (p.get("version") or "").lower()
            if fixed_generation is not None:
                applies = fixed_generation == generation
            elif not version:
                applies = True  # every version
            elif version.isdigit():
                applies = int(version) == generation
            else:
                applies = version.split("_")[0] == distro
            if applies:
                return "applies", f"affects ROS {generation} ({distro.capitalize()})"
        return None
    packages = sorted({p["product"] for p in products if p.get("vendor") in ROS_VENDORS})
    if packages:
        return "related", f"in the ROS package {packages[0]} - list it in an SBOM to check"
    return "related", "another product that mentions ROS"


def _cve_exposure(tags: set[str], components: list[tuple[str, str | None]],
                  database_url: str, ros_distro: str | None = None) -> list[dict[str, Any]]:
    """
    Real-world CVEs: the curated research notes plus NVD CVEs found by platform
    keyword search (the curated note wins when both have the same CVE).

    A CVE applies if it names a platform the device is built on (unitree,
    ros, ...) or lists one of its SBOM components among the affected products.
    A CVE that only shares an interface keyword (mqtt, wifi) is marked
    related: it's about some other product using that interface. Order:
    curated notes, component matches with the version listed, platform
    matches, other component matches, then related; within each, CISA
    known-exploited first, then by CVSS.
    """
    # Either source may be missing (no curated notes, NVD skipped, snapshot install).
    have_curated = tables_exist(["research_cves"], database_url)
    have_nvd = tables_exist(["nvd_cves"], database_url)
    parts = []
    if have_curated:
        parts.append("""
            SELECT id, cvss_rating AS score, description, platform_tags,
                   NULL::date AS kev, true AS curated
            FROM research_cves WHERE is_current""")
    if have_nvd:
        parts.append("""
            SELECT id, cvss_score AS score, description, platform_tags,
                   cisa_kev_added AS kev, false AS curated
            FROM nvd_cves WHERE is_current""" + ("""
              AND id NOT IN (SELECT id FROM research_cves WHERE is_current)""" if have_curated else ""))
    if not parts:
        return []
    cves = query("\nUNION ALL".join(parts), database_url=database_url)
    products = _affected_products(database_url) if have_nvd else {}
    rows = []
    for cve in cves:
        cve_tags = set(cve["platform_tags"] or [])
        platforms = sorted(cve_tags & PLATFORMS.keys() & tags)
        component = component_match(products.get(cve["id"], []), components)
        related = False
        if component and component[1] == "not_affected":
            continue  # about this component, but a version the device doesn't run
        ros_only = platforms == ["ros"] and not cve["curated"]  # curated notes are already about robots
        if component and component[1] == "affected":
            reason, band = f"your {component[0]} is listed as affected", 0.1
        elif platforms and not ros_only:
            reason, band = "built on " + ", ".join(PLATFORMS[p] for p in platforms), 0.2
        elif ros_only and not component:
            verdict = ros_match(products.get(cve["id"], []), ros_distro, cve["description"])
            if verdict is None:
                continue  # core ROS, but for another generation or distro
            reason, band, related = verdict[1], (0.2 if verdict[0] == "applies" else 0.6), verdict[0] == "related"
        elif component:
            reason, band = f"you use {component[0]} (version not checked)", 0.3
        elif not (cve_tags & PLATFORMS.keys()) and (shared := sorted(cve_tags & tags)):
            reason, band, related = "another product that also uses " + ", ".join(shared), 0.6, True
        else:
            continue
        score = cve["score"]
        severity = f"CVSS {score}" if score is not None else "real-world CVE"
        if cve["kev"]:
            severity += " · actively exploited (CISA KEV)"
        rows.append({
            "source": "cve",
            "ref_id": cve["id"],
            "title": cve["description"],
            "summary": summary(cve["description"]),
            "fixed_in": (fixed_version(products.get(cve["id"], []), *component_parts(component[0]))
                         if component else None),
            "component": component_parts(component[0])[0] if component else None,
            "severity": severity,
            "score": float(score) if score is not None else None,
            "kev": bool(cve["kev"]),
            "reason": reason,
            "related": related,
            # curated 0-0.1, then the bands above (all above EMB3D's 1+);
            # within a band KEV first, then higher score
            "rank": (0 if cve["curated"] and not related else band)
                    + (0 if cve["kev"] else 0.05)
                    + (10 - float(score if score is not None else 0)) / 200,
        })
    return rows


def _emb3d_exposure(property_ids: list[str], database_url: str) -> list[dict[str, Any]]:
    rows = []
    for t in query(THREATS_FOR_PROPERTIES_SQL, [property_ids], database_url=database_url):
        severity = t["maturity"] or "unrated"
        if t["cve_ids"]:
            n = len(t["cve_ids"])
            severity += f" · {n} CVE{'s' if n != 1 else ''}"
        via = [v.removeprefix("Device ") for v in t["via"]]
        reason = "your device " + via[0] + (f" (+{len(via) - 1} more)" if len(via) > 1 else "")
        rows.append({
            "source": "emb3d",
            "ref_id": t["id"],
            "title": t["name"],
            "severity": severity,
            "reason": reason,
            "rank": _EMB3D_RANK.get(t["maturity"], 4) - (0.5 if t["cve_ids"] else 0),
        })
    return rows


# ATLAS has ~100 top-level techniques seen in case studies, most only once.
# Showing all of them would bury the device-specific results.
ATLAS_TOP_TECHNIQUES = 10


def _atlas_exposure(database_url: str) -> list[dict[str, Any]]:
    """The top-level ATLAS techniques used most often in real-world case studies."""
    if not tables_exist(["atlas_techniques", "atlas_case_study_techniques"], database_url):
        return []
    return [
        {
            "source": "atlas",
            "ref_id": t["id"],
            "title": t["name"],
            "severity": f"used in {t['n']} case studies",
            "reason": "you run ML on the device",
            "rank": 5 + i / 100,  # keep most-used first
        }
        for i, t in enumerate(query(
            """
            SELECT t.id, t.name, count(DISTINCT cst.case_study_id) AS n
            FROM atlas_techniques t
            JOIN atlas_case_study_techniques cst ON cst.technique_id = t.id
            WHERE t.parent_technique_id IS NULL AND t.is_current AND cst.is_current
            GROUP BY t.id, t.name
            ORDER BY n DESC, t.id
            LIMIT %s
            """,
            [ATLAS_TOP_TECHNIQUES],
            database_url=database_url,
        ))
    ]


# --------------------------------------------------------------------------
# Research papers: what the literature says about a device, and how to test it
# --------------------------------------------------------------------------

# Relevant papers that apply to a device: they target one of its platforms,
# cover an EMB3D threat its properties expose, or (when it runs ML) an ATLAS
# technique. `why` lists every reason that matched.
PAPERS_FOR_DEVICE_SQL = """
    WITH matches AS (
        SELECT id AS paper_id, 'you use ' || platform AS why
        FROM research_papers, unnest(platforms) AS platform
        WHERE relevant AND platform = ANY(%(tags)s)
        UNION ALL
        SELECT pt.paper_id, 'covers ' || pt.threat_id
        FROM research_paper_emb3d_threats pt
        JOIN emb3d_property_threats ept ON ept.threat_id = pt.threat_id AND ept.is_current
        WHERE ept.property_id = ANY(%(property_ids)s)
        UNION ALL
        SELECT DISTINCT paper_id, 'you run ML'
        FROM research_paper_atlas_techniques
        WHERE %(ml)s
    )
    SELECT p.id, p.title, p.arxiv_url, p.plain_summary, p.evidence_level,
           p.physical_safety_impact, array_agg(DISTINCT m.why ORDER BY m.why) AS why
    FROM matches m
    JOIN research_papers p ON p.id = m.paper_id AND p.relevant AND p.is_current
    GROUP BY p.id, p.title, p.arxiv_url, p.plain_summary, p.evidence_level, p.physical_safety_impact
"""

# Stronger evidence first.
_EVIDENCE_RANK = {"in_the_wild": 0, "real_robot": 1, "simulation": 2, "theoretical": 3}


def _paper_exposure(tags: list[str], property_ids: list[str], ml: bool,
                    database_url: str) -> list[dict[str, Any]]:
    """Papers relevant to the device, ranked between EMB3D threats and ATLAS techniques."""
    if not tables_exist(PAPER_TABLES, database_url):
        return []
    rows = []
    for paper in query(PAPERS_FOR_DEVICE_SQL,
                       {"tags": list(tags), "property_ids": list(property_ids), "ml": ml},
                       database_url=database_url):
        evidence = (paper["evidence_level"] or "unrated").replace("_", " ")
        rows.append({
            "source": "paper",
            "ref_id": paper["id"],
            "title": paper["title"],
            "severity": evidence + (" · physical harm" if paper["physical_safety_impact"] else ""),
            "reason": "; ".join(paper["why"][:2]) + (f" (+{len(paper['why']) - 2})" if len(paper["why"]) > 2 else ""),
            "rank": 4.5 - (0.2 if paper["physical_safety_impact"] else 0)
                    + _EVIDENCE_RANK.get(paper["evidence_level"], 4) / 20,
        })
    return rows


def get_paper_checks(
    tags: list[str],
    property_ids: list[str],
    ml: bool,
    kinds: tuple[str, ...] = ("passive", "active", "manual_review"),
    database_url: str = DATABASE_URL,
) -> list[dict[str, Any]]:
    """
    Concrete checks from the research literature that apply to a device - for
    the assessment agent to plan. `kind` uses the agent's gating: passive
    checks may be automated; active ones need operator approval; manual_review
    is for a person. Each check cites its paper and why it applies.
    """
    if not tables_exist(PAPER_TABLES, database_url):
        return []
    return query(
        f"""
        WITH papers AS ({PAPERS_FOR_DEVICE_SQL})
        SELECT c.paper_id, papers.title AS paper_title, papers.arxiv_url, papers.why,
               c.check_number, c.title, c.kind, c.description, c.requires
        FROM research_paper_checks c
        JOIN papers ON papers.id = c.paper_id
        WHERE c.kind = ANY(%(kinds)s)
        ORDER BY c.kind, papers.physical_safety_impact DESC, c.paper_id, c.check_number
        """,
        {"tags": list(tags), "property_ids": list(property_ids), "ml": ml, "kinds": list(kinds)},
        database_url=database_url,
    )



def get_emb3d_threats(category: str | None = None) -> list[dict[str, Any]]:
    """Current EMB3D threats, optionally for one category (used by charts.py)."""
    sql = "SELECT * FROM emb3d_threats WHERE is_current"
    params: list[Any] = []
    if category is not None:
        sql += " AND category = %s"
        params.append(category)
    return query(sql, params)
