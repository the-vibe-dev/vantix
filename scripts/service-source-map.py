#!/usr/bin/env python3
"""Map observed service/product strings to likely upstream sources and research queries."""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass


@dataclass
class Candidate:
    project: str
    repo: str
    package: str
    ecosystem: str
    docs: str
    match: str


CATALOG = [
    Candidate("WordPress", "https://github.com/WordPress/WordPress", "wordpress", "php", "https://developer.wordpress.org/", "wordpress"),
    Candidate("Roundcube", "https://github.com/roundcube/roundcubemail", "roundcube", "php", "https://github.com/roundcube/roundcubemail/wiki", "roundcube"),
    Candidate("Kibana", "https://github.com/elastic/kibana", "kibana", "nodejs", "https://www.elastic.co/guide/en/kibana/current/index.html", "kibana"),
    Candidate("Grafana", "https://github.com/grafana/grafana", "grafana", "go", "https://grafana.com/docs/grafana/latest/", "grafana"),
    Candidate("Drupal", "https://github.com/drupal/drupal", "drupal", "php", "https://www.drupal.org/docs", "drupal"),
    Candidate("Joomla", "https://github.com/joomla/joomla-cms", "joomla", "php", "https://docs.joomla.org/", "joomla"),
    Candidate("phpMyAdmin", "https://github.com/phpmyadmin/phpmyadmin", "phpmyadmin", "php", "https://docs.phpmyadmin.net/", "phpmyadmin"),
    Candidate("Silverpeas", "https://github.com/Silverpeas/Silverpeas-Core", "silverpeas", "java", "https://www.silverpeas.org/", "silverpeas"),
    Candidate("Jenkins", "https://github.com/jenkinsci/jenkins", "jenkins", "java", "https://www.jenkins.io/doc/", "jenkins"),
    Candidate("Apache HTTP Server", "https://github.com/apache/httpd", "httpd", "c", "https://httpd.apache.org/docs/", "apache"),
    Candidate("Tomcat", "https://github.com/apache/tomcat", "tomcat", "java", "https://tomcat.apache.org/", "tomcat"),
    Candidate("Nginx", "https://github.com/nginx/nginx", "nginx", "c", "https://nginx.org/en/docs/", "nginx"),
    Candidate("Django", "https://github.com/django/django", "django", "python", "https://docs.djangoproject.com/", "django"),
    Candidate("Flask", "https://github.com/pallets/flask", "flask", "python", "https://flask.palletsprojects.com/", "flask"),
    Candidate("FastAPI", "https://github.com/fastapi/fastapi", "fastapi", "python", "https://fastapi.tiangolo.com/", "fastapi"),
    Candidate("Laravel", "https://github.com/laravel/framework", "laravel", "php", "https://laravel.com/docs", "laravel"),
    Candidate("Symfony", "https://github.com/symfony/symfony", "symfony", "php", "https://symfony.com/doc/current/index.html", "symfony"),
    Candidate("Metabase", "https://github.com/metabase/metabase", "metabase", "clojure", "https://www.metabase.com/docs/latest/", "metabase"),
    Candidate("GitLab", "https://github.com/gitlabhq/gitlabhq", "gitlab", "ruby", "https://docs.gitlab.com/", "gitlab"),
    Candidate("Confluence", "https://bitbucket.org/atlassian/confluence", "confluence", "java", "https://confluence.atlassian.com/", "confluence"),
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--service", help="Observed service/banner string")
    parser.add_argument("--product", help="Normalized product name")
    parser.add_argument("--version", help="Observed version")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    return parser.parse_args()


def normalize_product(service: str | None, product: str | None) -> str:
    if product:
        return product.strip().lower()
    if not service:
        return ""
    lowered = service.strip().lower()
    tokens = re.findall(r"[a-z][a-z0-9._-]+", lowered)
    return tokens[0] if tokens else lowered


def extract_version(service: str | None, version: str | None) -> str:
    if version:
        return version
    if not service:
        return ""
    match = re.search(r"\d+(?:\.\d+){1,3}", service)
    return match.group(0) if match else ""


def candidate_matches(product: str, service: str) -> list[Candidate]:
    haystack = f"{product} {service}".lower()
    return [candidate for candidate in CATALOG if candidate.match in haystack]


def build_queries(product: str, version: str, matches: list[Candidate]) -> list[str]:
    base = product or "unknown service"
    queries = [
        f"{base} {version} github".strip(),
        f"{base} {version} changelog".strip(),
        f"{base} {version} release notes".strip(),
        f"{base} {version} security fix".strip(),
        f"{base} {version} CVE".strip(),
        f"{base} {version} patch diff".strip(),
    ]
    for match in matches:
        queries.append(f"{match.project} {version} {match.package} advisory".strip())
        queries.append(f"{match.project} {version} auth xss sqli deserialization".strip())
    seen: set[str] = set()
    ordered: list[str] = []
    for item in queries:
        item = " ".join(item.split())
        if item and item not in seen:
            seen.add(item)
            ordered.append(item)
    return ordered


def main() -> int:
    args = parse_args()
    service = args.service or ""
    product = normalize_product(service, args.product)
    version = extract_version(service, args.version)
    matches = candidate_matches(product, service)
    payload = {
        "input": {
            "service": service,
            "product": product,
            "version": version,
        },
        "candidates": [asdict(candidate) for candidate in matches],
        "queries": build_queries(product, version, matches),
    }
    if args.format == "json":
        print(json.dumps(payload, indent=2))
        return 0

    print(f"product: {product or 'unknown'}")
    print(f"version: {version or 'unknown'}")
    if matches:
        print("candidates:")
        for candidate in matches:
            print(f"- {candidate.project}")
            print(f"  repo: {candidate.repo}")
            print(f"  package: {candidate.package}")
            print(f"  ecosystem: {candidate.ecosystem}")
            print(f"  docs: {candidate.docs}")
    else:
        print("candidates:")
        print("- no direct catalog match; use generic search queries")
    print("queries:")
    for query in payload["queries"]:
        print(f"- {query}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
