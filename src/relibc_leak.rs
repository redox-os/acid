use anyhow::Result;

pub fn test() -> Result<()> {
    loop {
        let mut thread_list = vec![];
        for i in 1..5 {
            thread_list.push(std::thread::spawn(move || outer_runner(i)));
        }
        while thread_list.iter().any(|t| !t.is_finished()) {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
}

fn outer_runner(threadnum: usize) {
    // println!("outer_runner {}", threadnum);
    eprintln!("outer_runner {}", threadnum);
    inner_runner(threadnum);
    // println!("outer_runner {} exiting", threadnum);
    eprintln!("outer_runner {} exiting", threadnum);
}

fn inner_runner(threadnum: usize) {
    // println!("start runner {}", threadnum);
    eprintln!("start runner {}", threadnum);
    std::thread::sleep(std::time::Duration::from_millis(1));
    // println!("end runner {}", threadnum);
    eprintln!("end runner {}", threadnum);
}
