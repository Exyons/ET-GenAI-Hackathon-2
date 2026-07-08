from prahari.live.bus import EventBus


def test_publish_delivers_to_subscribers():
    bus = EventBus()
    q = bus._new_queue()
    bus.publish({"type": "incident", "id": "inc-c553"})
    got = q.get_nowait()
    assert got["type"] == "incident"
    assert got["id"] == "inc-c553"


def test_drop_on_full_does_not_raise():
    bus = EventBus(maxsize=1)
    q = bus._new_queue()
    for i in range(5):  # publish beyond capacity — must not raise
        bus.publish({"type": "status", "n": i})
    assert q.qsize() == 1
