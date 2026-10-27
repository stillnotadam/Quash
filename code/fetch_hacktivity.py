"""List every disclosed curl HackerOne report via public hacktivity search, then fetch each body.

Writes data/hacktivity.csv (id, title, substate) and data/h1/<id>.json.
"""
import csv, json, os, time
import requests
from fetch_reports import fetch, ROOT

Q = ("query HacktivitySearchQuery($queryString: String!, $from: Int, $size: Int, $sort: SortInput!) "
     "{ search(index: CompleteHacktivityReportIndex, query_string: $queryString, from: $from, size: $size, sort: $sort) "
     "{ total_count nodes { ... on HacktivityDocument { report { databaseId: _id title substate } } } } }")


def list_all():
    out, start = [], 0
    while True:
        body = {"operationName": "HacktivitySearchQuery", "query": Q,
                "variables": {"queryString": "team:curl", "size": 100, "from": start,
                              "sort": {"field": "disclosed_at", "direction": "DESC"},
                              "product_area": "hacktivity", "product_feature": "overview"}}
        r = requests.post("https://hackerone.com/graphql", json=body, timeout=30).json()
        nodes = r["data"]["search"]["nodes"]
        total = r["data"]["search"]["total_count"]
        out += [n["report"] for n in nodes if n.get("report")]
        start += 100
        time.sleep(1)
        if start >= total or not nodes:
            return out


def main():
    reps = list_all()
    print("listed", len(reps))
    with open(os.path.join(ROOT, "data", "hacktivity.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["databaseId", "title", "substate"])
        w.writeheader()
        w.writerows(reps)
    for i, r in enumerate(reps):
        fetch(r["databaseId"])
        if i % 50 == 0:
            print(i)


if __name__ == "__main__":
    main()
