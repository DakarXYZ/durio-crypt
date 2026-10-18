//! S1 and S4 on the mini own layer (same fakeserver as the matrix-sdk-crypto spike).

use spike_msc::fakeserver::FakeServer;
use spike_vodozemac::OwnMachine;

fn ulid(t: &str) -> String {
    format!("01K{}", t.repeat(23)).chars().take(26).collect()
}
fn dev(t: &str) -> String {
    format!("01KD{}", t.repeat(22)).chars().take(26).collect()
}

#[test]
fn s01_dm_roundtrip() {
    let srv = FakeServer::new();
    let mut a = OwnMachine::new(&srv, &ulid("A"), &dev("A1"));
    let mut b = OwnMachine::new(&srv, &ulid("B"), &dev("B1"));
    a.upload_keys().unwrap();
    b.upload_keys().unwrap();
    let dm = ulid("C");
    srv.lock().unwrap().channel_set_members(&dm, &[&ulid("A"), &ulid("B")]);
    a.send(&dm, "привет").unwrap();
    assert_eq!(b.receive().unwrap(), 1);
    let m = srv.lock().unwrap().channel_messages(&dm).pop().unwrap();
    assert!(!m.encrypted.to_string().contains("привет"));
    assert_eq!(b.decrypt(&m).unwrap(), "привет");
    assert_eq!(a.decrypt(&m).unwrap(), "привет"); // own echo
    let mut forged = m.clone();
    forged.author = ulid("X");
    assert!(b.decrypt(&forged).is_err());
}

#[test]
fn s04_rotation_on_member_and_device_removal() {
    let srv = FakeServer::new();
    let mut a = OwnMachine::new(&srv, &ulid("A"), &dev("A1"));
    let mut b1 = OwnMachine::new(&srv, &ulid("B"), &dev("B1"));
    let mut b2 = OwnMachine::new(&srv, &ulid("B"), &dev("B2"));
    let mut c = OwnMachine::new(&srv, &ulid("C"), &dev("C1"));
    let mut d = OwnMachine::new(&srv, &ulid("D"), &dev("D1"));
    for x in [&mut a, &mut b1, &mut b2, &mut c, &mut d] {
        x.upload_keys().unwrap();
    }
    let g = ulid("G");
    let all = [ulid("A"), ulid("B"), ulid("C"), ulid("D")];
    let refs: Vec<&str> = all.iter().map(String::as_str).collect();
    srv.lock().unwrap().channel_set_members(&g, &refs);
    a.send(&g, "m1").unwrap();
    let m1 = srv.lock().unwrap().channel_messages(&g).pop().unwrap();
    for x in [&mut b1, &mut b2, &mut c, &mut d] {
        x.receive().unwrap();
        assert_eq!(x.decrypt(&m1).unwrap(), "m1");
    }
    srv.lock()
        .unwrap()
        .channel_set_members(&g, &[&ulid("A"), &ulid("B"), &ulid("D")]);
    a.send(&g, "m2").unwrap();
    let m2 = srv.lock().unwrap().channel_messages(&g).pop().unwrap();
    assert_ne!(m1.encrypted["session_id"], m2.encrypted["session_id"]);
    c.receive().unwrap();
    assert!(c.decrypt(&m2).is_err());
    b2.receive().unwrap();
    assert_eq!(b2.decrypt(&m2).unwrap(), "m2");

    srv.lock().unwrap().device_delete(&ulid("B"), &dev("B2"));
    a.send(&g, "m3").unwrap();
    let m3 = srv.lock().unwrap().channel_messages(&g).pop().unwrap();
    assert_ne!(m2.encrypted["session_id"], m3.encrypted["session_id"]);
    assert!(b2.decrypt(&m3).is_err());
    for x in [&mut b1, &mut d] {
        x.receive().unwrap();
        assert_eq!(x.decrypt(&m3).unwrap(), "m3");
    }
}
