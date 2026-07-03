from prahari.data.lanl_slice import redteam_in_window, slice_auth_lines


def test_slice_auth_lines_keeps_window_and_stops_early():
    lines = [
        "100,U1@D,U1@D,C1,C2,Kerberos,Network,LogOn,Success",
        "200,U1@D,U1@D,C1,C2,Kerberos,Network,LogOn,Success",
        "300,U2@D,U2@D,C3,C4,NTLM,Network,LogOn,Success",
        "400,U2@D,U2@D,C3,C4,NTLM,Network,LogOn,Success",
    ]
    out = list(slice_auth_lines(iter(lines), t0=200, t1=400))
    # keeps times 200 and 300; 400 is excluded (half-open) and stops there
    assert [ln.split(",")[0] for ln in out] == ["200", "300"]


def test_redteam_in_window():
    rt = {("150", "U1@D", "C1", "C2"), ("500", "U9@D", "C8", "C9")}
    assert redteam_in_window(rt, 100, 300) == {("150", "U1@D", "C1", "C2")}
