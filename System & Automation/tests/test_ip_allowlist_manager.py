from pathlib import Path
import importlib.util

spec=importlib.util.spec_from_file_location("mgr", Path(__file__).parents[1]/"python"/"ip_allowlist_manager.py")
mgr=importlib.util.module_from_spec(spec); spec.loader.exec_module(mgr)

nets=[mgr.ipaddress.ip_network("10.10.10.0/24"), mgr.ipaddress.ip_network("192.0.2.0/28")]
result=mgr.evaluate_allowlist(["10.10.10.5","10.10.10.5","192.0.2.25","bad"],nets)
assert result["approved"] == ["10.10.10.5"]
assert result["duplicates"] == ["10.10.10.5"]
assert result["unauthorized"] == ["192.0.2.25"]
assert result["invalid"] == ["bad"]
print("PASS: allowlist evaluation")
