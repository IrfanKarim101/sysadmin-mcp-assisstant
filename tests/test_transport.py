import pytest

from sysadmin_mcp.transport import AsyncSSHTransport, _read_bounded_stream


class FakeReader:
    def __init__(self, chunks: list[str]) -> None:
        self.chunks = iter(chunks)

    async def read(self, size: int) -> str:
        del size
        return next(self.chunks, "")


@pytest.mark.asyncio
async def test_stream_reader_stops_at_utf8_byte_limit() -> None:
    stopped: list[bool] = []
    output, truncated = await _read_bounded_stream(
        FakeReader(["ab", "éé", "ignored"]), 5, lambda: stopped.append(True)
    )
    assert output == "abé"
    assert len(output.encode()) == 4
    assert truncated is True
    assert stopped == [True]


@pytest.mark.asyncio
async def test_stream_reader_preserves_complete_bounded_output() -> None:
    output, truncated = await _read_bounded_stream(
        FakeReader(["one", "two", ""]), 10, lambda: pytest.fail("unexpected stop")
    )
    assert output == "onetwo"
    assert truncated is False


@pytest.mark.parametrize(
    "kwargs",
    [{"timeout_seconds": 0}, {"timeout_seconds": -1}, {"max_output_bytes": 0}],
)
def test_transport_rejects_invalid_limits(kwargs) -> None:
    with pytest.raises(ValueError, match="positive"):
        AsyncSSHTransport(**kwargs)
