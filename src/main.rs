fn main() {
    let args: Vec<String> = std::env::args().collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match pakeles::cli::main_with(&args) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::exit(2);
        }
    }
}
