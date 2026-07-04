from prahari.data.lanl_slice import lines_for_hosts


def test_lines_for_hosts_filters_by_column_and_window():
    proc = [
        "150001,U1@D,C999,P1,Start",
        "150562,C1003$@D,C1003,P47,Start",   # host match (col 2)
        "150900,U2@D,C1003,P7,Start",        # host match
        "160000,U3@D,C1003,P8,Start",        # out of window -> stop
    ]
    out = list(lines_for_hosts(iter(proc), hosts={"C1003"}, t0=150000, t1=160000, host_fields=(2,)))
    assert [l.split(",")[0] for l in out] == ["150562", "150900"]
