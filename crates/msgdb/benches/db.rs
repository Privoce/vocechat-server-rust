use criterion::{criterion_group, criterion_main, Criterion};
use rc_msgdb::MsgDb;
use tempfile::tempdir;

fn send_benchmark(c: &mut Criterion) {
    let dir = tempdir().unwrap();
    let db = MsgDb::open(dir.path()).unwrap();
    let to = (0..50000i64).collect::<Vec<_>>();
    let msg = b"hello!";
    c.bench_function("send", |b| {
        b.iter(|| {
            db.messages()
                .send_to_group(1, to.iter().copied(), msg)
                .unwrap();
        })
    });
}

fn fetch_benchmark(c: &mut Criterion) {
    let dir = tempdir().unwrap();
    let db = MsgDb::open(dir.path()).unwrap();
    let to = vec![1];
    let msg = b"hello!";
    for _ in 0..1000 {
        db.messages()
            .send_to_group(1, to.iter().copied(), msg)
            .unwrap();
    }
    c.bench_function("fetch", |b| {
        b.iter(|| {
            assert_eq!(
                db.messages()
                    .fetch_user_messages_after(1, None, 10000)
                    .unwrap()
                    .len(),
                1000
            );
        })
    });
}

criterion_group!(benches, send_benchmark, fetch_benchmark);
criterion_main!(benches);
