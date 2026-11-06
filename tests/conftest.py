import importlib.util
import os
import shutil

import pytest


def _have_tools() -> bool:
    from cpslab.util import ToolError, cosign, gpg, scii_agent
    try:
        cosign(), gpg(), scii_agent()
    except ToolError:
        return False
    return shutil.which("git") is not None and importlib.util.find_spec("scii") is not None


HAVE_TOOLS = _have_tools()
need_tools = pytest.mark.skipif(not HAVE_TOOLS and not os.environ.get("CPSLAB_REQUIRE_TOOLS"),
                                reason="нужны cosign, gpg, git, scii-agent и scii-gate")


@pytest.fixture(scope="session")
def lab(tmp_path_factory):
    if not HAVE_TOOLS:
        if os.environ.get("CPSLAB_REQUIRE_TOOLS"):
            pytest.fail("CPSLAB_REQUIRE_TOOLS задан, но инструментов нет")
        pytest.skip("нужны cosign, gpg, git, scii-agent и scii-gate")
    from cpslab.scenarios import Lab
    home = tmp_path_factory.mktemp("lab")
    lab = Lab(home).init(progress=lambda m: None)
    yield lab
    lab.keys.close()
