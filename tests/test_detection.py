import sys, os
import importlib
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
l4s = importlib.import_module("log4shell-detector", "Log4ShellDetector")

def test_full_path():  
    l4sd = l4s.Log4ShellDetector(maximum_distance=20, debug=False, quick=False)
    detections = l4sd.scan_path("./tests")
    assert detections == 8

def test_url_encoded():  
    l4sd = l4s.Log4ShellDetector(maximum_distance=20, debug=False, quick=False)
    matches = l4sd.scan_file("./tests/test-cases/test-url-encoded.log")
    assert len(matches) == 3