///Acid testing program

extern crate x86;

fn switch_test() -> Result<(), String> {
    use std::thread;
    use std::time::Instant;
    use x86::time::rdtscp;

    let switch_thread = thread::spawn(|| {
        for i in 0..100 {
            let time = Instant::now();
            let tsc = unsafe { rdtscp() };
            thread::yield_now();
            let dtsc = unsafe { rdtscp() } - tsc;
            let dtime = time.elapsed();
            print!("{}", format!("C: {}: {} ns: {} ticks\n", i, dtime.as_secs() * 1000000000 + dtime.subsec_nanos() as u64, dtsc));
        }
    });

    for i in 0..100 {
        let time = Instant::now();
        let tsc = unsafe { rdtscp() };
        thread::yield_now();
        let dtsc = unsafe { rdtscp() } - tsc;
        let dtime = time.elapsed();
        print!("{}", format!("P: {}: {} ns: {} ticks\n", i, dtime.as_secs() * 1000000000 + dtime.subsec_nanos() as u64, dtsc));
    }

    let _ = switch_thread.join();

    Ok(())
}

fn thread_test() -> Result<(), String> {
    use std::process::Command;
    use std::thread;
    use std::time::Instant;

    println!("Trying to stop kernel...");

    let start = Instant::now();
    while start.elapsed().as_secs() == 0 {}

    println!("Kernel preempted!");

    println!("Trying to kill kernel...");

    let mut threads = Vec::new();
    for i in 0..10 {
        threads.push(thread::spawn(move || {
            let mut sub_threads = Vec::new();
            for j in 0..10 {
                sub_threads.push(thread::spawn(move || {
                    Command::new("sh")
                        .arg("-c")
                        .arg(&format!("echo {}:{}", i, j))
                        .spawn().unwrap()
                        .wait().unwrap();
                }));
            }

            Command::new("sh")
                .arg("-c")
                .arg(&format!("echo {}", i))
                .spawn().unwrap()
                .wait().unwrap();

            for sub_thread in sub_threads {
                let _ = sub_thread.join();
            }
        }));
    }

    for thread in threads {
        let _ = thread.join();
    }

    println!("Kernel survived thread test!");

    Ok(())
}

fn main() {
    use std::collections::BTreeMap;
    use std::{env, process};
    use std::time::Instant;

    let mut tests: BTreeMap<&'static str, fn() -> Result<(), String>> = BTreeMap::new();
    tests.insert("switch", switch_test);
    tests.insert("thread", thread_test);

    for arg in env::args().skip(1) {
        if let Some(test) = tests.get(&arg.as_str()) {
            let time = Instant::now();
            let res = test();
            let elapsed = time.elapsed();
            match res {
                Ok(_) => {
                    println!("acid: {}: passed: {} ns", arg, elapsed.as_secs() * 1000000000 + elapsed.subsec_nanos() as u64);
                },
                Err(err) => {
                    println!("acid: {}: failed: {}", arg, err);
                }
            }
        } else {
            println!("acid: {}: not found", arg);
            process::exit(1);
        }
    }

}
