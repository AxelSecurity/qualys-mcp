"""CVE exposure via VMDR host detections (works without CSAM)."""

import qualys.api as api
import qualys.aggregators as agg
from qualys.workflows import investigate as inv


def _xml(hosts, truncated=False):
    """Build a minimal VMDR host-detection XML response.
    hosts: list of (host_id, ip, dns, os, [(qid, severity, qds), ...])"""
    out = ["<HOST_LIST_VM_DETECTION_OUTPUT><RESPONSE><HOST_LIST>"]
    for hid, ip, dns, os_, dets in hosts:
        out.append(f"<HOST><ID>{hid}</ID><IP>{ip}</IP><DNS>{dns}</DNS><OS>{os_}</OS><DETECTION_LIST>")
        for qid, sev, qds in dets:
            out.append(f"<DETECTION><QID>{qid}</QID><SEVERITY>{sev}</SEVERITY>"
                       f"<STATUS>Active</STATUS><QDS>{qds}</QDS></DETECTION>")
        out.append("</DETECTION_LIST></HOST>")
    out.append("</HOST_LIST>")
    if truncated:
        out.append("<WARNING><CODE>1980</CODE><TEXT>more</TEXT></WARNING>")
    out.append("</RESPONSE></HOST_LIST_VM_DETECTION_OUTPUT>")
    return "".join(out).encode()


class TestGetHostsForQids:
    def test_batches_all_qids_and_merges_hosts(self, monkeypatch):
        urls = []

        def fake_get(url, timeout=30, **kw):
            urls.append(url)
            if "qids=1," in url:  # first batch
                return _xml([("10", "10.0.0.1", "web01", "Ubuntu", [(1, 5, 90)])])
            return _xml([("10", "10.0.0.1", "web01", "Ubuntu", [(60, 4, 50)]),
                         ("20", "10.0.0.2", "", "RHEL", [(61, 5, 95)])])

        monkeypatch.setattr(api, "api_get", fake_get)
        res = api.get_hosts_for_qids(list(range(1, 74)), use_cache=False)

        assert len(urls) == 2  # 73 QIDs -> batches of 50 + 23
        assert res["ok"] is True
        assert res["qidsChecked"] == 73
        assert res["hostCount"] == 2
        assert res["detectionCount"] == 3
        web01 = next(h for h in res["hosts"] if h["hostId"] == "10")
        assert sorted(web01["qids"]) == [1, 60]
        assert web01["maxSeverity"] == 5
        assert res["hosts"][0]["hostId"] == "20"  # highest QDS first
        assert res["qidMaxQds"] == {1: 90, 60: 50, 61: 95}

    def test_follows_truncation_pagination(self, monkeypatch):
        calls = []

        def fake_get(url, timeout=30, **kw):
            calls.append(url)
            if "id_min" not in url:
                return _xml([("5", "10.0.0.5", "a", "", [(7, 5, 10)])], truncated=True)
            assert "id_min=6" in url
            return _xml([("9", "10.0.0.9", "b", "", [(7, 5, 10)])])

        monkeypatch.setattr(api, "api_get", fake_get)
        res = api.get_hosts_for_qids([7], use_cache=False)
        assert len(calls) == 2
        assert res["hostCount"] == 2

    def test_failure_is_reported_and_not_cached(self, monkeypatch):
        monkeypatch.setattr(api, "api_get", lambda url, timeout=30, **kw: None)
        res = api.get_hosts_for_qids([424242])
        assert res["ok"] is False
        assert res["failedBatches"] == 1
        assert not any(k.startswith("hosts_for_qids_") and "424242" in k for k in api.DETECTION_CACHE)

    def test_empty_qids(self):
        res = api.get_hosts_for_qids([])
        assert res["ok"] is True and res["hostCount"] == 0


class TestCveAggUsesAllQids:
    def test_investigate_cve_agg_queries_every_qid(self, monkeypatch):
        seen = {}
        monkeypatch.setattr(agg, "get_cve_qids", lambda cve: [101, 102, 103])
        monkeypatch.setattr(agg, "get_kb_batch", lambda qids: {})
        monkeypatch.setattr(agg, "get_qds_for_qids", lambda qids: {})
        monkeypatch.setattr(agg, "module_available", lambda m: m != "csam")

        def fake_hosts(qids):
            seen["qids"] = list(qids)
            return {"hosts": [{"hostId": "1", "ip": "10.1.1.1", "hostname": "app01", "os": "Linux",
                               "qids": [103], "maxSeverity": 5, "maxQds": 0}],
                    "hostCount": 1, "detectionCount": 1, "qidsChecked": 3,
                    "failedBatches": 0, "ok": True}

        monkeypatch.setattr(agg, "get_hosts_for_qids", fake_hosts)
        res = agg.investigate_cve_agg("CVE-2026-0001", detail="detailed")
        assert seen["qids"] == [101, 102, 103]
        assert res["confirmedHosts"]["hostCount"] == 1
        assert res["confirmedHosts"]["lookupOk"] is True
        assert res["summary"]["csamAvailable"] is False


    def test_detection_qds_replaces_zero_kb_qds(self, monkeypatch):
        monkeypatch.setattr(agg, "get_cve_qids", lambda cve: [101, 102])
        monkeypatch.setattr(agg, "get_kb_batch", lambda qids: {
            101: {"qid": 101, "title": "OpenJDK RCE", "severity": 5, "qds": 0, "cves": []},
            102: {"qid": 102, "title": "OpenJDK RCE (b)", "severity": 4, "qds": 0, "cves": []}})
        monkeypatch.setattr(agg, "get_qds_for_qids", lambda qids: {})  # e.g. failed with 409
        monkeypatch.setattr(agg, "module_available", lambda m: m != "csam")
        monkeypatch.setattr(agg, "get_hosts_for_qids", lambda qids: {
            "hosts": [], "hostCount": 0, "detectionCount": 2, "qidsChecked": 2,
            "qidMaxQds": {102: 95}, "failedBatches": 0, "ok": True})
        res = agg.investigate_cve_agg("CVE-2026-0002", detail="detailed")
        assert res["qds"] == 95
        assert res["qdsSource"] == "vmdr_detections"
        by_qid = {e["qid"]: e["qds"] for e in res["allKbDetails"]}
        assert by_qid == {101: 0, 102: 95}

    def test_kb_qds_kept_when_higher(self, monkeypatch):
        monkeypatch.setattr(agg, "get_cve_qids", lambda cve: [101])
        monkeypatch.setattr(agg, "get_kb_batch", lambda qids: {
            101: {"qid": 101, "title": "X", "severity": 5, "qds": 0, "cves": []}})
        monkeypatch.setattr(agg, "get_qds_for_qids", lambda qids: {101: 98})
        monkeypatch.setattr(agg, "module_available", lambda m: m != "csam")
        monkeypatch.setattr(agg, "get_hosts_for_qids", lambda qids: {
            "hosts": [], "hostCount": 0, "detectionCount": 1, "qidsChecked": 1,
            "qidMaxQds": {101: 70}, "failedBatches": 0, "ok": True})
        res = agg.investigate_cve_agg("CVE-2026-0003", detail="detailed")
        assert res["qds"] == 98
        assert "qdsSource" not in res


class TestAssessExposureWithoutCsam:
    def test_unknown_not_not_exposed(self, monkeypatch):
        monkeypatch.setattr(agg, "get_cve_qids", lambda cve: [1])
        monkeypatch.setattr(agg, "get_kb_batch", lambda qids: {
            1: {"qid": 1, "title": "OpenJDK RCE", "severity": 5, "qds": 0, "cves": ["CVE-X"],
                "patch_available": True, "has_exploit": False, "ransomware": False}})
        monkeypatch.setattr(agg, "module_available", lambda m: m != "csam")

        def boom(*a, **k):
            raise AssertionError("csam_count must not be called without CSAM")

        monkeypatch.setattr(agg, "csam_count", boom)
        res = agg.assess_exposure(cve="CVE-X")
        assert res["exposure"]["status"] == "unknown"
        assert res["exposure"]["csamAvailable"] is False
        assert "CSAM" in res["summary"]


class TestRendering:
    def _cve_deep(self, confirmed):
        return {"cve": "CVE-2026-1", "title": "OpenJDK RCE", "severity": 5, "qds": 0,
                "patchAvailable": True, "qids": list(range(1, 74)),
                "summary": {"csamAvailable": False}, "confirmedHosts": confirmed}

    def test_summary_lists_affected_hosts(self):
        confirmed = {"hostCount": 2, "lookupOk": True, "searchedBy": "VMDR detections for 73 QIDs",
                     "hosts": [{"hostId": "1", "ip": "10.0.0.1", "hostname": "web01", "os": "Ubuntu"},
                               {"hostId": "2", "ip": "10.0.0.2", "hostname": "", "os": ""}]}
        s = inv._summarize({"cve_deep": self._cve_deep(confirmed)})
        text = " | ".join(s["key_findings"])
        assert "2 host(s) with open VMDR detections" in text
        assert "web01 (10.0.0.1, Ubuntu)" in text
        assert "10.0.0.2" in text
        assert s["stats"]["confirmedAffectedHosts"] == 2
        assert s["stats"]["csam"].startswith("not available")

    def test_summary_reports_zero_and_failure_distinctly(self):
        ok = inv._summarize({"cve_deep": self._cve_deep(
            {"hostCount": 0, "lookupOk": True, "searchedBy": "x", "hosts": []})})
        assert any("No hosts with open VMDR detections" in f for f in ok["key_findings"])
        bad = inv._summarize({"cve_deep": self._cve_deep(
            {"hostCount": 0, "lookupOk": False, "searchedBy": "x", "hosts": []})})
        assert any("lookup" in f and "failed" in f for f in bad["key_findings"])

    def test_correlation_lists_all_qids(self):
        corr = inv._correlate({"cve_deep": self._cve_deep({})})
        finding = corr[0]["finding"]
        assert "73 QID(s)" in finding
        assert finding.endswith("73")
        assert "1, 2, 3" in finding


class TestCveNotInKb:
    def _data(self):
        return {"cve_deep": {"cve": "CVE-2026-123891", "qids": [], "severity": 0, "qds": 0,
                             "patchAvailable": False, "summary": {"qidCount": 0}}}

    def test_summary_says_not_found_instead_of_zero_severity(self):
        s = inv._summarize(self._data())
        assert "not found in the Qualys Knowledge Base" in s["headline"]
        assert "severity 0" not in s["headline"]
        assert s["risk_level"] == "unknown"
        assert s["stats"]["inKnowledgeBase"] is False

    def test_no_compensating_controls_action(self):
        actions = inv._build_actions(self._data(), [])
        assert len(actions) == 1
        assert "compensating controls" not in actions[0]["action"]
        assert "Verify CVE-2026-123891" in actions[0]["action"]

    def test_known_cve_unchanged(self):
        data = {"cve_deep": {"cve": "CVE-2026-1", "qids": [1], "title": "X", "severity": 5,
                             "qds": 95, "patchAvailable": True, "summary": {}}}
        s = inv._summarize(data)
        assert "severity 5, QDS 95" in s["headline"]
        assert inv._build_actions(data, [])[0]["action"] == "Apply available patch for CVE-2026-1"


class TestDetectionApiVersion:
    def test_constant_is_v4(self):
        assert api.DETECTION_API_PATH == "/api/4.0/fo/asset/host/vm/detection/"

    def test_no_v2_detection_path_left(self):
        import pathlib
        src = pathlib.Path(api.__file__).read_text()
        assert "/api/2.0/fo/asset/host/vm/detection/" not in src

    def test_all_detection_callers_hit_v4(self, monkeypatch):
        urls = []

        def fake_get(url, timeout=30, **kw):
            urls.append(url)
            return _xml([])

        monkeypatch.setattr(api, "api_get", fake_get)
        api.get_hosts_for_qids([1], use_cache=False)
        api.get_detections(severity=5, use_cache=False)
        api.get_detections_by_qds(qds_min=70, use_cache=False)
        api.QDS_CACHE.clear()
        api.get_qds_for_qids([777001])
        api.get_host_detections("999001", severity=4, days=1)
        assert len(urls) == 5
        assert all("/api/4.0/fo/asset/host/vm/detection/?action=list" in u for u in urls)
        # concurrency semaphore still recognises the v4 path
        assert "/fo/asset/host/vm/detection/" in urls[0]
