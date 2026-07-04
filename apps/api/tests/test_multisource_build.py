from prahari.data.multisource import build_incidents


def test_build_fuses_three_sources_on_one_host():
    auth = ["150885,U620@DOM1,U620@DOM1,C17693,C1003,NTLM,Network,LogOn,Success"]
    proc = ["150900,U620@DOM1,C1003,P7,Start"]
    flow = ["151000,3,C1003,N93,C5074,443,6,10,4200"]
    redteam = {("150885", "U620@DOM1", "C17693", "C1003")}

    incidents = build_incidents(auth, proc, flow, redteam, window_seconds=600)
    c1003 = next(i for i in incidents if i.entity == "C1003")

    assert len(c1003.sources) == 3            # lanl + lanl_proc + lanl_flow
    assert len(c1003.phases) == 3             # lateral + execution + c2
    assert c1003.high_confidence is True
    assert c1003.is_true_positive is True     # red-team auth carried the label
