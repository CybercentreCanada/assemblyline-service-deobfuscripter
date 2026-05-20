"""Deobfuscripter Unit Tests"""

import pytest
from deobfuscripter.deobfuscripter import DeobfuScripter


@pytest.mark.parametrize(
    ("text", "output"),
    [
        (b"", b""),
        (b"no xor here", b"no xor here"),
        (b'xor(\"0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A\", \"boffe*C*kg*k*rexon*~or~\")', b'"hello I am a xored text"')
    ],
)
def test_simple_xor_function(text: bytes, output: bytes) -> None:
    assert DeobfuScripter.simple_xor_function(text) == output
